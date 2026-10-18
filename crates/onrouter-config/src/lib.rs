//! ONRouter configuration: Nginx 风格配置的词法器与解析器。
//!
//! 语法示例：
//! ```text
//! listen 8080;
//! server_name localhost;
//!
//! location /api {
//!     content_by_lua_file "lua/hello.lua";
//!     proxy_pass "http://127.0.0.1:9000";
//! }
//! ```

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// 单条配置指令：`name args...;` 或 `name args... { ... }`
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    /// 仅块指令非空
    pub block: Vec<Directive>,
    /// 指令所在行号（报错/日志用）
    pub line: usize,
}

impl Directive {
    pub fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(|s| s.as_str())
    }

    pub fn find(&self, name: &str) -> Option<&Directive> {
        self.block.iter().find(|d| d.name == name)
    }
}

/// 顶层配置 = 一个虚拟的根 Directive
#[derive(Debug, Clone)]
pub struct Config {
    pub root: Directive,
}

/// nginx 完整布局兼容：顶层 http{} 的内容展平到根（ONRouter 原生写法没有 http 包装），
/// events{} 无对应语义直接丢弃。学习/迁移 nginx.conf 时二者可原样喂给 ONRouter。
fn flatten_nginx_wrapper(block: Vec<Directive>) -> Vec<Directive> {
    let mut out: Vec<Directive> = Vec::with_capacity(block.len());
    for d in block {
        match d.name.as_str() {
            "http" => out.extend(flatten_nginx_wrapper(d.block)),
            "events" => {}
            _ => out.push(d),
        }
    }
    out
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let block = parse_fragment(input)?;
        Ok(Config {
            root: Directive {
                name: "root".to_string(),
                args: vec![],
                block: flatten_nginx_wrapper(block),
                line: 1,
            },
        })
    }

    /// 从文件加载：以该文件所在目录为基准解析 `include <pattern>;`（支持 `*` 通配），
    /// 把被包含文件的内容就地拼接进指令树。
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let block = parse_fragment(&text)?;
        let base = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
        let block = expand_includes(block, &base, 0)?;
        Ok(Config {
            root: Directive {
                name: "root".to_string(),
                args: vec![],
                block: flatten_nginx_wrapper(block),
                line: 1,
            },
        })
    }

    pub fn find(&self, name: &str) -> Option<&Directive> {
        self.root.find(name)
    }

    /// 所有 server 块
    pub fn servers(&self) -> impl Iterator<Item = &Directive> {
        self.root.block.iter().filter(|d| d.name == "server")
    }
}

/// 解析一段配置文本为指令列表（不做 http{} 展平、不做 include 展开——由调用方处理）。
fn parse_fragment(input: &str) -> Result<Vec<Directive>, ConfigError> {
    let rewritten = rewrite_lua_blocks(input)?;
    let tokens = lex(&rewritten)?;
    let mut parser = Parser { tokens, pos: 0 };
    parser.parse_block(None)
}

// ---------- *_by_lua_block 预处理 ----------
//
// OpenResty 的 `content_by_lua_block { ...lua... }` 里是裸 Lua 源码：块内可能出现
// `}`、`;`、`#`、引号和注释，直接交给 nginx 风格词法器会被切碎。这里在词法分析前
// 把块替换成等价的 `content_by_lua "…转义后的 Lua…";`，后续解析器无需感知 Lua。
// 替换时保留块内换行数，使后续指令的 line 仍与原文件一致。

/// 把 `*_by_lua_block { <lua> }` 改写为 `*_by_lua "<lua>";`。
fn rewrite_lua_blocks(input: &str) -> Result<String, ConfigError> {
    let bytes = input.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(input.len() + 16);
    let mut i = 0usize;
    let mut line = 1usize;
    let mut at_stmt_start = true;
    // (基础指令名, 指令起始行)，如 ("content_by_lua", 12)
    let mut pending: Option<(String, usize)> = None;

    while i < n {
        let b = bytes[i];
        match b {
            b'\n' => {
                out.push('\n');
                line += 1;
                i += 1;
            }
            _ if b.is_ascii_whitespace() => {
                out.push(b as char);
                i += 1;
            }
            b'#' => {
                let start = i;
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
                out.push_str(&input[start..i]);
            }
            b'"' | b'\'' => {
                let start = i;
                i = skip_config_quoted(bytes, i);
                out.push_str(&input[start..i]);
                at_stmt_start = false;
            }
            b'{' => {
                if let Some((base, dir_line)) = pending.take() {
                    let content_start = i + 1;
                    let (content_end, after_close) =
                        capture_lua_block(bytes, content_start).ok_or_else(|| ConfigError::Parse {
                            line: dir_line,
                            message: format!("Lua 块缺少 '}}'（directive '{base}_block'）"),
                        })?;
                    let lua = &input[content_start..content_end];
                    let newlines = lua.bytes().filter(|&c| c == b'\n').count();
                    out.push('"');
                    escape_lua_into(lua, &mut out);
                    out.push_str("\";");
                    // 补回块内换行，保证后续指令行号不变
                    for _ in 0..newlines {
                        out.push('\n');
                    }
                    line += newlines;
                    i = after_close;
                } else {
                    out.push('{');
                    i += 1;
                }
                at_stmt_start = true;
            }
            b'}' | b';' => {
                out.push(b as char);
                i += 1;
                at_stmt_start = true;
                pending = None;
            }
            _ => {
                let start = i;
                while i < n {
                    let c = bytes[i];
                    if c.is_ascii_whitespace()
                        || matches!(c, b'{' | b'}' | b';' | b'#' | b'"' | b'\'')
                    {
                        break;
                    }
                    i += 1;
                }
                let word = &input[start..i];
                if at_stmt_start && word.ends_with("_by_lua_block") {
                    let base = &word[..word.len() - "_block".len()];
                    out.push_str(base);
                    pending = Some((base.to_string(), line));
                } else {
                    out.push_str(word);
                }
                at_stmt_start = false;
            }
        }
    }
    Ok(out)
}

/// 跳过配置层的引号字符串（与 lexer 相同的转义规则），返回闭合引号之后的位置。
fn skip_config_quoted(bytes: &[u8], mut i: usize) -> usize {
    let quote = bytes[i];
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    i
}

/// 从 `{` 之后开始扫描 Lua 源码，返回 (闭合 `}` 的位置, 闭合之后的位置)。
/// 理解短字符串、长括号字符串 `[=[...]=]`、行注释与嵌套表花括号。
fn capture_lua_block(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut depth = 1usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => i = skip_lua_short_string(bytes, i),
            b'[' => match skip_lua_long_bracket(bytes, i) {
                Some(after) => i = after,
                None => i += 1,
            },
            b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                i += 2;
                match skip_lua_long_bracket(bytes, i) {
                    Some(after) => i = after,
                    None => {
                        while i < bytes.len() && bytes[i] != b'\n' {
                            i += 1;
                        }
                    }
                }
            }
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((i, i + 1));
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn skip_lua_short_string(bytes: &[u8], mut i: usize) -> usize {
    let quote = bytes[i];
    i += 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i = (i + 2).min(bytes.len()),
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// 若 `bytes[i]` 起是 Lua 长括号（`[[`、`[=[` …），返回配对闭合之后的位置。
fn skip_lua_long_bracket(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'[') {
        return None;
    }
    let mut i = start + 1;
    let mut eq = 0usize;
    while i < bytes.len() && bytes[i] == b'=' {
        eq += 1;
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'[' {
        return None;
    }
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b']' {
            let mut j = i + 1;
            let mut k = 0usize;
            while j < bytes.len() && k < eq && bytes[j] == b'=' {
                k += 1;
                j += 1;
            }
            if k == eq && j < bytes.len() && bytes[j] == b']' {
                return Some(j + 1);
            }
        }
        i += 1;
    }
    // 未闭合的长括号：吞掉剩余内容，交给 Lua 运行时报语法错
    Some(bytes.len())
}

/// 把 Lua 源码转义成配置 lexer 能还原的引号串内容。
fn escape_lua_into(code: &str, out: &mut String) {
    let mut chars = code.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                    out.push_str("\\n");
                } else {
                    out.push_str("\\r");
                }
            }
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
}

/// `include` 最大递归深度（防止自包含 / 环）——对齐 nginx "cyclic include" 保护的意图。
const MAX_INCLUDE_DEPTH: usize = 32;

/// 递归展开指令树里的 `include <pattern>;`。非 glob 的 include 若文件不存在则报错
/// （对齐 nginx：静默漏读配置是难排查故障）；glob 无匹配则视为空。
fn expand_includes(dirs: Vec<Directive>, base: &Path, depth: usize) -> Result<Vec<Directive>, ConfigError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(ConfigError::Parse {
            line: 0,
            message: format!("include 递归超过 {MAX_INCLUDE_DEPTH} 层（疑似循环 include）"),
        });
    }
    let mut out: Vec<Directive> = Vec::with_capacity(dirs.len());
    for d in dirs {
        if d.name == "include" {
            let patterns: Vec<&str> = d.args.iter().map(|s| s.as_str()).collect();
            if patterns.is_empty() {
                return Err(ConfigError::Parse {
                    line: d.line,
                    message: "include 需要一个文件/通配参数".to_string(),
                });
            }
            for pat in patterns {
                for file in resolve_include(pat, base, d.line)? {
                    let text = std::fs::read_to_string(&file)?;
                    let inner = parse_fragment(&text)?;
                    // 被包含文件里的相对 include 仍以主配置的目录为基准（对齐 nginx 的 prefix 语义）
                    out.extend(expand_includes(inner, base, depth + 1)?);
                }
            }
            continue;
        }
        // 块指令：递归展开其内部（location / server 里的 include 片段）
        let block = if d.block.is_empty() {
            Vec::new()
        } else {
            expand_includes(d.block, base, depth)?
        };
        out.push(Directive { block, ..d });
    }
    Ok(out)
}

/// 把一个 include 模式解析成具体文件列表。`base` 为主配置所在目录。
/// 模式含 `*` → 在其父目录内做文件名通配匹配并排序（确定性）；不含 `*` → 单文件，缺失即报错。
fn resolve_include(pat: &str, base: &Path, line: usize) -> Result<Vec<PathBuf>, ConfigError> {
    let joined = base.join(pat);
    if !pat.contains('*') {
        if joined.is_file() {
            return Ok(vec![joined]);
        }
        return Err(ConfigError::Parse {
            line,
            message: format!("include 文件不存在：{}", joined.display()),
        });
    }
    // 拆出目录部分与文件名通配（只支持最后一段带 `*`，够用且不易误配）
    let (dir, name_glob) = match joined.parent() {
        Some(p) => (p.to_path_buf(), joined.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()),
        None => (PathBuf::from("."), pat.to_string()),
    };
    let mut files = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            let mut names: Vec<String> = Vec::new();
            for e in entries.flatten() {
                if let Some(n) = e.file_name().to_str() {
                    if glob_match(&name_glob, n) && e.path().is_file() {
                        names.push(n.to_string());
                    }
                }
            }
            names.sort();
            files = names.into_iter().map(|n| dir.join(n)).collect();
        }
        // 通配无目录可枚举 → 视为空（不像单文件那样报错，符合 glob include 的宽松语义）
        Err(_) => {}
    }
    Ok(files)
}

/// 极简 `*` 通配符匹配（`*` 匹配任意长度，含空）。大小写敏感（与文件系统排序一致）。
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // 动态规划：dp[i][j] = pattern[..i] 是否匹配 text[..j]
    let (m, n) = (p.len(), t.len());
    let mut dp = vec![vec![false; n + 1]; m + 1];
    dp[0][0] = true;
    for i in 1..=m {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
            for j in 1..=n {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            }
        } else {
            for j in 1..=n {
                dp[i][j] = dp[i - 1][j - 1] && p[i - 1] == t[j - 1];
            }
        }
    }
    dp[m][n]
}

// ---------- 词法器 ----------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// 标识符或裸词参数
    Word(String),
    /// 引号字符串参数
    Quoted(String),
    /// `{`
    OpenBrace,
    /// `}`
    CloseBrace,
    /// `;`
    Semicolon,
}

fn lex(input: &str) -> Result<Vec<(Token, usize)>, ConfigError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut line = 1usize;
    let n = chars.len();

    while i < n {
        let c = chars[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => i += 1,
            '#' => {
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
            }
            '{' => {
                tokens.push((Token::OpenBrace, line));
                i += 1;
            }
            '}' => {
                tokens.push((Token::CloseBrace, line));
                i += 1;
            }
            ';' => {
                tokens.push((Token::Semicolon, line));
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < n {
                    let ch = chars[i];
                    if ch == '\\' && i + 1 < n {
                        let next = chars[i + 1];
                        s.push(match next {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    if ch == '\n' {
                        line += 1;
                    }
                    s.push(ch);
                    i += 1;
                }
                if !closed {
                    return Err(ConfigError::Parse {
                        line,
                        message: "unterminated string literal".into(),
                    });
                }
                tokens.push((Token::Quoted(s), line));
            }
            _ => {
                let mut s = String::new();
                while i < n {
                    let ch = chars[i];
                    if ch.is_whitespace() || "{};#".contains(ch) {
                        break;
                    }
                    s.push(ch);
                    i += 1;
                }
                tokens.push((Token::Word(s), line));
            }
        }
    }
    Ok(tokens)
}

// ---------- 解析器 ----------

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&(Token, usize)> {
        self.tokens.get(self.pos)
    }

    fn parse_block(&mut self, term: Option<usize>) -> Result<Vec<Directive>, ConfigError> {
        let mut directives = Vec::new();
        loop {
            let (tok, line) = match self.peek() {
                Some(t) => t.clone(),
                None => {
                    if term.is_some() {
                        let eof_line = self.tokens.last().map(|t| t.1).unwrap_or(1);
                        return Err(ConfigError::Parse {
                            line: eof_line,
                            message: "unexpected end of file, missing '}'".into(),
                        });
                    }
                    return Ok(directives);
                }
            };
            match tok {
                Token::CloseBrace => {
                    if term.is_none() {
                        return Err(ConfigError::Parse {
                            line,
                            message: "unexpected '}'".into(),
                        });
                    }
                    self.pos += 1;
                    return Ok(directives);
                }
                Token::Semicolon => {
                    // 空指令（分号前无内容），跳过
                    self.pos += 1;
                }
                Token::Word(name) | Token::Quoted(name) => {
                    self.pos += 1;
                    let mut args = Vec::new();
                    let block;
                    loop {
                        match self.peek() {
                            Some((Token::Word(a), _)) | Some((Token::Quoted(a), _)) => {
                                args.push(a.clone());
                                self.pos += 1;
                            }
                            Some((Token::Semicolon, _)) => {
                                self.pos += 1;
                                block = Vec::new();
                                break;
                            }
                            Some((Token::OpenBrace, _)) => {
                                self.pos += 1;
                                block = self.parse_block(Some(line))?;
                                break;
                            }
                            Some((Token::CloseBrace, l)) => {
                                return Err(ConfigError::Parse {
                                    line: *l,
                                    message: format!(
                                        "directive '{name}' not terminated by ';'"
                                    ),
                                });
                            }
                            None => {
                                return Err(ConfigError::Parse {
                                    line,
                                    message: format!(
                                        "directive '{name}' not terminated by ';'"
                                    ),
                                });
                            }
                        }
                    }
                    directives.push(Directive { name, args, block, line });
                }
                Token::OpenBrace => {
                    return Err(ConfigError::Parse {
                        line,
                        message: "unexpected '{{' at statement start".into(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        # 注释
        worker_processes auto;

        server {
            listen 8080;
            server_name localhost;

            location /api {
                content_by_lua_file "lua/api.lua";
            }

            location /static {
                root "public";
            }
        }
    "#;

    #[test]
    fn parses_sample() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let server = cfg.servers().next().unwrap();
        assert_eq!(server.find("listen").unwrap().arg(0), Some("8080"));
        assert_eq!(server.find("server_name").unwrap().arg(0), Some("localhost"));
    }

    #[test]
    fn finds_location() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let server = cfg.servers().next().unwrap();
        let loc = server.block.iter().find(|d| d.name == "location").unwrap();
        assert_eq!(loc.arg(0), Some("/api"));
        assert!(loc.find("content_by_lua_file").is_some());
    }

    #[test]
    fn rejects_unclosed_block() {
        let err = Config::parse("server { listen 80;").unwrap_err();
        assert!(err.to_string().contains("missing '}'"));
    }

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("*.conf", "a.conf"));
        assert!(glob_match("*.conf", ".conf"));
        assert!(!glob_match("*.conf", "a.txt"));
        assert!(glob_match("server*.conf", "server12.conf"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exact2"));
    }

    #[test]
    fn quoted_token_can_start_a_statement() {
        // nginx `map` 允许用引号串作匹配分支的模式（含空串 `""`）；解析器须把它当作指令名
        let cfg = Config::parse("map $http_a $b { default x; \"\" close; }").unwrap();
        let m = cfg.root.block.iter().find(|d| d.name == "map").unwrap();
        assert_eq!(m.arg(0), Some("$http_a"));
        assert_eq!(m.arg(1), Some("$b"));
        let names: Vec<&str> = m.block.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["default", ""]);
        // 空模式的结果参数
        let empty = m.block.iter().find(|d| d.name == "").unwrap();
        assert_eq!(empty.arg(0), Some("close"));
    }

    fn lua_of(cfg: &Config, name: &str) -> String {
        let server = cfg.servers().next().unwrap();
        let loc = server.block.iter().find(|d| d.name == "location").unwrap();
        loc.find(name).unwrap().arg(0).unwrap().to_string()
    }

    #[test]
    fn lua_block_becomes_inline_lua_directive() {
        let cfg = Config::parse(
            r#"
            init_by_lua_block { local x = 1 }

            server {
                location / {
                    content_by_lua_block {
                        ngx.say("hi")
                    }
                }
            }
            "#,
        )
        .unwrap();
        let init = cfg.root.block.iter().find(|d| d.name == "init_by_lua").unwrap();
        assert_eq!(init.arg(0).unwrap().trim(), "local x = 1");
        let lua = lua_of(&cfg, "content_by_lua");
        assert!(lua.contains(r#"ngx.say("hi")"#), "{lua:?}");
        // 原指令块不应残留
        let server = cfg.servers().next().unwrap();
        let loc = server.block.iter().find(|d| d.name == "location").unwrap();
        assert!(loc.find("content_by_lua_block").is_none());
    }

    #[test]
    fn lua_block_understands_nested_tables_strings_and_comments() {
        let cfg = Config::parse(
            r#"
            server {
                location / {
                    content_by_lua_block {
                        local t = { a = 1, b = { c = "}" } }
                        -- comment with } and ;
                        local s = [[ long } string ]]
                        local n = #t
                        ngx.say("ok; { }")
                    }
                }
            }
            "#,
        )
        .unwrap();
        let lua = lua_of(&cfg, "content_by_lua");
        assert!(lua.contains(r#"b = { c = "}" }"#), "{lua:?}");
        assert!(lua.contains("-- comment with } and ;"), "{lua:?}");
        assert!(lua.contains("[[ long } string ]]"), "{lua:?}");
        assert!(lua.contains("local n = #t"), "{lua:?}");
        assert!(lua.contains(r#"ngx.say("ok; { }")"#), "{lua:?}");
    }

    #[test]
    fn lua_block_understands_long_brackets_and_single_quotes() {
        let cfg = Config::parse(
            "server { location / { content_by_lua_block {\n\
             --[==[ long } comment ; # ]==]\n\
             local x = [=[a ]= b]=]\n\
             local y = 'it\\'s a } brace'\n\
             ngx.say(x, y)\n\
             } } }",
        )
        .unwrap();
        let lua = lua_of(&cfg, "content_by_lua");
        assert!(lua.contains("--[==[ long } comment ; # ]==]"), "{lua:?}");
        assert!(lua.contains("[=[a ]= b]=]"), "{lua:?}");
        assert!(lua.contains(r"local y = 'it\'s a } brace'"), "{lua:?}");
    }

    #[test]
    fn lua_block_preserves_escape_sequences() {
        let cfg = Config::parse(
            r#"server { location / { content_by_lua_block { ngx.say("a\nb\t\"c\"") } } }"#,
        )
        .unwrap();
        let lua = lua_of(&cfg, "content_by_lua");
        assert!(lua.contains(r#"ngx.say("a\nb\t\"c\"")"#), "{lua:?}");
    }

    #[test]
    fn lua_block_preserves_following_line_numbers() {
        let src = "server {\n\
                   \x20 location / {\n\
                   \x20   content_by_lua_block {\n\
                   \x20     ngx.say(1)\n\
                   \x20     ngx.say(2)\n\
                   \x20   }\n\
                   \x20   return 204;\n\
                   \x20 }\n\
                   }\n";
        let cfg = Config::parse(src).unwrap();
        let server = cfg.servers().next().unwrap();
        let loc = server.block.iter().find(|d| d.name == "location").unwrap();
        assert_eq!(loc.find("content_by_lua").unwrap().line, 3);
        assert_eq!(loc.find("return").unwrap().line, 7);
    }

    #[test]
    fn lua_block_requires_closing_brace() {
        let err =
            Config::parse("server { location / { content_by_lua_block { ngx.say(1) ").unwrap_err();
        assert!(err.to_string().contains("Lua 块缺少 '}'"), "{err}");
    }

    #[test]
    fn include_splices_single_file_and_glob() {
        // 建一个临时目录：<tmp>/main.conf + <tmp>/parts/{one,two}.conf + skipped.txt
        let unique = format!("onrouter-include-test-{}-{}", std::process::id(), line!());
        let dir = std::env::temp_dir().join(unique);
        let parts = dir.join("parts");
        std::fs::create_dir_all(&parts).unwrap();
        std::fs::write(dir.join("main.conf"), "server {\n  include parts/*.conf;\n  include extra.conf;\n}\n").unwrap();
        std::fs::write(parts.join("one.conf"), "listen 8081;").unwrap();
        std::fs::write(parts.join("two.conf"), "listen 8082;").unwrap();
        std::fs::write(parts.join("skipped.txt"), "listen 9999;").unwrap();
        std::fs::write(dir.join("extra.conf"), "server_name inc.local;").unwrap();

        let cfg = Config::load(dir.join("main.conf")).unwrap();
        let server = cfg.servers().next().unwrap();
        let listens: Vec<&str> = server
            .block
            .iter()
            .filter(|d| d.name == "listen")
            .map(|d| d.arg(0).unwrap())
            .collect();
        // glob 命中 one/two（按名排序），不含 skipped.txt；单文件 extra 也在
        assert_eq!(listens, vec!["8081", "8082"]);
        assert_eq!(server.find("server_name").unwrap().arg(0), Some("inc.local"));
        // 展开后指令树里不应残留 include
        assert!(server.find("include").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn include_missing_single_file_errors() {
        let unique = format!("onrouter-include-missing-{}", line!());
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.conf"), "include nope.conf;\n").unwrap();
        let err = Config::load(dir.join("main.conf")).unwrap_err();
        assert!(err.to_string().contains("include 文件不存在"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
