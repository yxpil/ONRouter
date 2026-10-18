//! 运行时全局设置：连接、超时、TLS、优雅停机等运维参数。
//!
//! 配置指令（顶层，与 nginx 同名）：
//! ```text
//! worker_connections 10240;
//! client_header_timeout 15s;
//! client_body_timeout 30s;
//! keepalive_timeout 65s;
//! keepalive_requests 1000;
//! tls_handshake_timeout 10s;
//! shutdown_grace 30s;
//! server_tokens on;
//! tcp_nodelay on;
//! accept_backlog 512;
//! gzip on;
//! gzip_min_length 20;
//! gzip_comp_level 1;
//! gzip_types text/css application/json;
//! reload 2s;
//! ```

use std::time::Duration;

use onrouter_config::Config;

#[derive(Debug, Clone)]
pub struct Settings {
    /// 全局并发连接上限（对标 nginx worker_connections，此处为整个进程）
    pub worker_connections: usize,
    /// 读请求头超时
    pub client_header_timeout: Duration,
    /// 读请求体超时（单帧之间的最大间隔）
    pub client_body_timeout: Duration,
    /// keep-alive 空闲超时
    pub keepalive_timeout: Duration,
    /// 单连接最多处理多少请求后关闭
    pub keepalive_requests: usize,
    /// TLS 握手超时
    pub tls_handshake_timeout: Duration,
    /// 收到停机信号后等在途请求的最长时间，超时后强制断开
    pub shutdown_grace: Duration,
    /// 是否在响应里带 Server 头
    pub server_tokens: bool,
    pub tcp_nodelay: bool,
    pub accept_backlog: u32,
    /// 响应 gzip 压缩参数
    pub gzip: GzipSettings,
    /// `reload <interval>;`：配置热重载的轮询间隔（mtime 变化才真正重载）。
    /// None = 不自动重载（unix 仍可用 SIGHUP 触发），Some(d) = 每 d 检查一次配置。
    pub reload: Option<Duration>,
}

/// 响应体 gzip 压缩配置（对标 nginx ngx_http_gzip_module）
#[derive(Debug, Clone)]
pub struct GzipSettings {
    /// gzip on/off（nginx 默认 off）
    pub enabled: bool,
    /// 小于此字节数的响应不压缩（nginx gzip_min_length，默认 20）
    pub min_length: usize,
    /// 压缩级别 1-9（nginx gzip_comp_level，默认 1）
    pub comp_level: u32,
    /// 可压缩的 MIME 类型（小写；text/html 始终包含，与 nginx 一致）
    pub types: Vec<String>,
}

/// nginx 内置始终压缩的类型，无法通过 gzip_types 移除
pub const GZIP_ALWAYS: &str = "text/html";

/// ONRouter 开箱即用的默认压缩类型集合（nginx 默认只有 text/html，这里给一份实用超集）
fn default_gzip_types() -> Vec<String> {
    [
        GZIP_ALWAYS,
        "text/css",
        "text/plain",
        "text/xml",
        "application/json",
        "application/javascript",
        "application/xml",
        "text/javascript",
        "image/svg+xml",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for GzipSettings {
    fn default() -> Self {
        GzipSettings {
            enabled: false,
            min_length: 20,
            comp_level: 1,
            types: default_gzip_types(),
        }
    }
}

impl GzipSettings {
    /// 响应 Content-Type 是否属于可压缩类型（忽略 `; charset=` 等参数，大小写不敏感）
    pub fn eligible_content_type(&self, content_type: &str) -> bool {
        let main = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if main.is_empty() {
            return false;
        }
        self.types.iter().any(|t| t == &main)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            worker_connections: 10240,
            client_header_timeout: Duration::from_secs(15),
            client_body_timeout: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(65),
            keepalive_requests: 1000,
            tls_handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(30),
            server_tokens: true,
            tcp_nodelay: true,
            accept_backlog: 512,
            gzip: GzipSettings::default(),
            reload: None,
        }
    }
}

/// 解析 nginx 风格时间：`500ms` / `15s` / `1m` / `2h` / 纯数字按秒
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n.trim(), 1_000_000u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n.trim(), 1_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n.trim(), 60_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n.trim(), 3_600_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('d') {
        (n.trim(), 86_400_000_000_000u64)
    } else {
        (s, 1_000_000_000u64)
    };
    num.parse::<f64>()
        .ok()
        .filter(|v| *v >= 0.0 && *v < 86_400.0 * 365.0)
        .map(|v| Duration::from_nanos((v * mult as f64) as u64))
}

fn on_off(v: Option<&str>) -> Option<bool> {
    match v?.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

impl Settings {
    /// 从配置读取设置；无法识别或非法的值不致命，作为告警返回（对标 nginx 的 warn 日志）
    pub fn from_config(config: &Config) -> (Settings, Vec<String>) {
        let mut s = Settings::default();
        let mut warnings = Vec::new();

        if let Some(d) = config.find("worker_connections") {
            match d.arg(0).and_then(|v| v.parse::<usize>().ok()) {
                Some(n) if n > 0 => s.worker_connections = n,
                _ => warnings.push("worker_connections 取值非法，使用默认值".to_string()),
            }
        }
        for (name, slot) in [
            ("client_header_timeout", &mut s.client_header_timeout),
            ("client_body_timeout", &mut s.client_body_timeout),
            ("keepalive_timeout", &mut s.keepalive_timeout),
            ("tls_handshake_timeout", &mut s.tls_handshake_timeout),
            ("shutdown_grace", &mut s.shutdown_grace),
        ] {
            if let Some(v) = config.find(name).and_then(|d| d.arg(0)) {
                match parse_duration(v) {
                    Some(d) => *slot = d,
                    None => warnings.push(format!("{name} 时间格式非法: {v}")),
                }
            }
        }
        if let Some(v) = config.find("keepalive_requests").and_then(|d| d.arg(0)) {
            s.keepalive_requests = v.parse::<usize>().unwrap_or(1000).max(1);
        }
        for (name, slot) in [
            ("server_tokens", &mut s.server_tokens),
            ("tcp_nodelay", &mut s.tcp_nodelay),
        ] {
            if let Some(d) = config.find(name) {
                match on_off(d.arg(0)) {
                    Some(v) => *slot = v,
                    None => warnings.push(format!("{name} 只接受 on/off，已忽略")),
                }
            }
        }
        if let Some(v) = config.find("accept_backlog").and_then(|d| d.arg(0)) {
            s.accept_backlog = v.parse::<u32>().unwrap_or(512).clamp(16, 65535);
        }
        if let Some(d) = config.find("gzip") {
            match on_off(d.arg(0)) {
                Some(v) => s.gzip.enabled = v,
                None => warnings.push("gzip 只接受 on/off，已忽略".to_string()),
            }
        }
        if let Some(v) = config.find("gzip_min_length").and_then(|d| d.arg(0)) {
            match v.parse::<usize>() {
                Ok(n) => s.gzip.min_length = n,
                Err(_) => warnings.push(format!("gzip_min_length 取值非法: {v}")),
            }
        }
        if let Some(v) = config.find("gzip_comp_level").and_then(|d| d.arg(0)) {
            match v.parse::<u32>() {
                Ok(n @ 1..=9) => s.gzip.comp_level = n,
                _ => warnings.push(format!("gzip_comp_level 应在 1-9 之间，已忽略: {v}")),
            }
        }
        // gzip_types 是多值指令：`gzip_types a b c;`。text/html 始终压缩，故强制保留。
        if let Some(d) = config.find("gzip_types") {
            let mut types = vec![GZIP_ALWAYS.to_string()];
            for a in &d.args {
                let t = a.trim().to_ascii_lowercase();
                if t.is_empty() || t == GZIP_ALWAYS {
                    continue;
                }
                if !types.contains(&t) {
                    types.push(t);
                }
            }
            s.gzip.types = types;
        }

        // reload：配置热重载轮询间隔。`reload 2s;` 每 2s 检查 mtime；`reload on;` 默认 1s；
        // `reload off;`（默认）不自动重载，但 unix 仍可用 SIGHUP 触发。
        if let Some(v) = config.find("reload").and_then(|d| d.arg(0)) {
            match v.to_ascii_lowercase().as_str() {
                "off" => s.reload = None,
                "on" => s.reload = Some(Duration::from_secs(1)),
                other => match parse_duration(other) {
                    Some(d) => s.reload = Some(d.max(Duration::from_millis(200))),
                    None => warnings.push(format!(
                        "reload 取值非法: {other}（应为 on/off 或时长，如 2s）"
                    )),
                },
            }
        }

        // hyper 的 http1 只有一个读头超时，它同时覆盖"慢速发头"与"keep-alive 空闲"，
        // 因此取两者较大值：否则 keep-alive 空闲会被 header 超时提前掐断导致频繁重连。
        s.client_header_timeout = s.client_header_timeout.max(s.keepalive_timeout);
        (s, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("1500ms"), Some(Duration::from_millis(1500)));
        assert_eq!(parse_duration("15s"), Some(Duration::from_secs(15)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("10"), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("-5s"), None);
    }

    #[test]
    fn header_timeout_at_least_keepalive() {
        let cfg = Config::parse("client_header_timeout 5s; keepalive_timeout 60s;").unwrap();
        let (s, _) = Settings::from_config(&cfg);
        assert_eq!(s.client_header_timeout, Duration::from_secs(60));
        assert_eq!(s.keepalive_timeout, Duration::from_secs(60));
    }

    #[test]
    fn gzip_defaults_off() {
        let cfg = Config::parse("").unwrap();
        let (s, warnings) = Settings::from_config(&cfg);
        assert!(!s.gzip.enabled);
        assert!(warnings.is_empty());
        assert!(s.gzip.types.contains(&"text/html".to_string()));
    }

    #[test]
    fn parses_gzip_directives() {
        let cfg = Config::parse(
            "gzip on; gzip_min_length 100; gzip_comp_level 6; gzip_types application/json text/css;",
        )
        .unwrap();
        let (s, warnings) = Settings::from_config(&cfg);
        assert!(s.gzip.enabled);
        assert_eq!(s.gzip.min_length, 100);
        assert_eq!(s.gzip.comp_level, 6);
        // text/html 强制保留，即使没在 gzip_types 里列出
        assert!(s.gzip.types.contains(&"text/html".to_string()));
        assert!(s.gzip.types.contains(&"application/json".to_string()));
        assert!(s.gzip.types.contains(&"text/css".to_string()));
        assert!(warnings.is_empty());
    }

    #[test]
    fn gzip_rejects_bad_values_with_warning() {
        let cfg = Config::parse("gzip maybe; gzip_comp_level 99;").unwrap();
        let (s, warnings) = Settings::from_config(&cfg);
        assert!(!s.gzip.enabled); // 非法 on/off → 保持默认 off
        assert_eq!(s.gzip.comp_level, 1); // 越界级别被忽略
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn reload_parses_variants() {
        let (s, _) = Settings::from_config(&Config::parse("").unwrap());
        assert_eq!(s.reload, None); // 默认不自动重载

        let (s, _) = Settings::from_config(&Config::parse("reload on;").unwrap());
        assert_eq!(s.reload, Some(Duration::from_secs(1)));

        let (s, _) = Settings::from_config(&Config::parse("reload 2s;").unwrap());
        assert_eq!(s.reload, Some(Duration::from_secs(2)));

        // 下限：过短的间隔被抬到 200ms，避免忙轮询
        let (s, _) = Settings::from_config(&Config::parse("reload 50ms;").unwrap());
        assert_eq!(s.reload, Some(Duration::from_millis(200)));

        let (s, warnings) = Settings::from_config(&Config::parse("reload banana;").unwrap());
        assert_eq!(s.reload, None);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn eligible_content_type_ignores_charset() {
        let g = GzipSettings {
            enabled: true,
            types: vec!["text/html".into(), "application/json".into()],
            ..Default::default()
        };
        assert!(g.eligible_content_type("application/json; charset=utf-8"));
        assert!(g.eligible_content_type("TEXT/HTML"));
        assert!(!g.eligible_content_type("image/png"));
        assert!(!g.eligible_content_type(""));
    }
}
