//! 代理**响应头**重写：对标 nginx `proxy_redirect` 与 `proxy_cookie_domain`/`proxy_cookie_path`。
//!
//! 这些都是配置期即可完全决定的字符串改写（不依赖运行时请求上下文）：
//! * `proxy_redirect`：改写上游返回的 `Location` / `Refresh` 头。
//!   - `proxy_redirect off` → 关闭。
//!   - `proxy_redirect default` → 一条合成规则：把上游来源前缀（proxy_pass 的 `scheme://authority`）
//!     换成对外前缀（location 的匹配路径），产出**相对** Location（正是 nginx 默认的常见效果）。
//!   - `proxy_redirect <redirect> <replacement>`（可重复）→ 逐条改写。`redirect` 以 `~` 开头视作正则
//!     （替换串支持 `$1`/`${name}`/`$0`），否则按**前缀**匹配。
//! * `proxy_cookie_domain` / `proxy_cookie_path`：改写 `Set-Cookie` 里的 `domain=` / `path=` 属性。
//!   条目形如 `<old> <new>`；`new` 为字面量 `none` 表示删除该属性；`old` 以 `~` 开头视作正则；
//!   domain 的字面量匹配忽略大小写并容忍前导点；path 的字面量匹配是**前缀**替换。
//!   `proxy_cookie_domain off` / `proxy_cookie_path off` → 关闭。

use regex::Regex;

/// 一条匹配模式：正则或字面量前缀。
#[derive(Debug, Clone)]
pub enum MatchPattern {
    Literal(String),
    Regex(Regex),
}

impl MatchPattern {
    /// 解析配置里的 token：`~regex` → Regex（编译失败返回 None，由调用方告警）；否则字面量。
    pub fn from_token(tok: &str) -> Option<MatchPattern> {
        if let Some(re) = tok.strip_prefix('~') {
            Regex::new(re).ok().map(MatchPattern::Regex)
        } else {
            Some(MatchPattern::Literal(tok.to_string()))
        }
    }
}

/// `proxy_redirect` 的一条规则：匹配模式 + 替换串（字面量，或正则替换模板）。
#[derive(Debug, Clone)]
pub struct RedirectRule {
    pub m: MatchPattern,
    pub replacement: String,
}

/// `proxy_redirect` 整体配置。
#[derive(Debug, Clone, Default)]
pub struct ProxyRedirect {
    /// `off` 显式关闭（或未启用时默认 false，配合 rules 为空即无效果）。
    pub off: bool,
    /// 有效规则（含 `default` 合成出的规则）。为空 = 不改写。
    pub rules: Vec<RedirectRule>,
}

/// 把 Location/Refresh 头值按规则改写；第一条命中即返回。无命中或关闭返回 None（保持原值）。
pub fn apply_redirect(rules: &[RedirectRule], value: &str) -> Option<String> {
    for r in rules {
        match &r.m {
            MatchPattern::Literal(prefix) => {
                if value.starts_with(prefix.as_str()) {
                    let rest = &value[prefix.len()..];
                    // 拼接时折叠接缝双斜杠：`/v1/` + `/login` → `/v1/login`
                    let out = if r.replacement.ends_with('/') && rest.starts_with('/') {
                        format!("{}{}", &r.replacement[..r.replacement.len() - 1], rest)
                    } else {
                        format!("{}{}", r.replacement, rest)
                    };
                    return Some(out);
                }
            }
            MatchPattern::Regex(re) => {
                if re.is_match(value) {
                    return Some(re.replace_all(value, r.replacement.as_str()).into_owned());
                }
            }
        }
    }
    None
}

/// 属性类改写规则（domain/path）：模式 + 新值 + 是否删除。
#[derive(Debug, Clone)]
pub struct CookieAttrRule {
    pub m: MatchPattern,
    pub replacement: String,
    pub remove: bool,
}

/// 一组 Set-Cookie 改写规则。
#[derive(Debug, Clone, Default)]
pub struct CookieRewrite {
    pub off: bool,
    pub rules: Vec<CookieAttrRule>,
}

/// domain 字面量比较：忽略大小写、忽略前导点。
fn domain_equalish(a: &str, b: &str) -> bool {
    let trim = |s: &str| s.trim_start_matches('.').to_ascii_lowercase();
    trim(a) == trim(b)
}

/// 改写单个 Set-Cookie 串里指定属性（domain/path）。返回新串；未命中/关闭则原样返回。
/// attr_name 传 "domain" 或 "path"。
pub fn rewrite_cookie_attr(cookie: &str, cfg: &CookieRewrite, attr_name: &str) -> String {
    if cfg.off || cfg.rules.is_empty() {
        return cookie.to_string();
    }
    // 按 ';' 切段：第 0 段是 name=value，其余是属性。
    let mut parts: Vec<String> = cookie.split(';').map(|p| p.to_string()).collect();
    let attr_prefix = format!("{}=", attr_name);
    let mut changed = false;
    let mut remove_idx: Option<usize> = None;
    for (i, seg) in parts.iter_mut().enumerate() {
        if i == 0 {
            continue; // 跳过 cookie 本体
        }
        let trimmed = seg.trim_start();
        if !trimmed.to_ascii_lowercase().starts_with(&attr_prefix) {
            continue;
        }
        let cur_val = trimmed[attr_prefix.len()..].trim();
        for rule in &cfg.rules {
            let matched = match &rule.m {
                MatchPattern::Literal(old) => {
                    if attr_name == "domain" {
                        domain_equalish(cur_val, old)
                    } else {
                        // path：前缀匹配
                        cur_val.starts_with(old.as_str())
                    }
                }
                MatchPattern::Regex(re) => re.is_match(cur_val),
            };
            if !matched {
                continue;
            }
            if rule.remove {
                remove_idx = Some(i);
            } else {
                let new_val = match &rule.m {
                    MatchPattern::Literal(old) => {
                        if attr_name == "domain" {
                            // domain：整值替换
                            rule.replacement.clone()
                        } else {
                            // path：仅替换匹配到的前缀，保留尾部
                            format!("{}{}", rule.replacement, &cur_val[old.len()..])
                        }
                    }
                    MatchPattern::Regex(re) => re.replace_all(cur_val, rule.replacement.as_str()).into_owned(),
                };
                // 保留原段的分隔与空白风格，规范为 "; name=val"
                *seg = format!(" {}={}", attr_name, new_val);
            }
            changed = true;
            break;
        }
        if changed {
            break;
        }
    }
    if let Some(idx) = remove_idx {
        parts.remove(idx);
    }
    parts.join(";")
}

/// 把 `proxy_pass <target>` 规约为来源前缀 `scheme://authority`（用于 `proxy_redirect default`）。
/// 非 http(s) 或解析失败返回 None。
pub fn upstream_origin(proxy_pass: &str) -> Option<String> {
    let rest = proxy_pass.trim();
    let (scheme, after) = rest.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = after.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    Some(format!("{}://{}", scheme, authority))
}

/// 由 location 匹配 pattern 推出对外前缀（`proxy_redirect default` 的替换串）。
/// pattern 里可能带正则前缀（`~`/`=` 等）——只取字面路径部分；无斜杠则补 `/`。
pub fn public_prefix(pattern: &str) -> String {
    let p = pattern.trim();
    let p = p.trim_start_matches('=').trim_start_matches("~*").trim_start_matches('^');
    if p.is_empty() || !p.starts_with('/') {
        "/".to_string()
    } else if p.ends_with('/') {
        p.to_string()
    } else {
        format!("{}/", p)
    }
}

/// 生成 `proxy_redirect default` 的合成规则（上游来源前缀 → 对外前缀）。
pub fn default_redirect_rule(proxy_pass: &str, pattern: &str) -> Option<RedirectRule> {
    let origin = upstream_origin(proxy_pass)?;
    Some(RedirectRule {
        m: MatchPattern::Literal(origin),
        replacement: public_prefix(pattern),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(prefix: &str, repl: &str) -> RedirectRule {
        RedirectRule { m: MatchPattern::Literal(prefix.into()), replacement: repl.into() }
    }

    #[test]
    fn redirect_prefix_and_regex_and_default() {
        // 前缀替换
        let rules = vec![lit("http://backend.internal:8080", "http://public.example")];
        assert_eq!(
            apply_redirect(&rules, "http://backend.internal:8080/a/b?c=1").as_deref(),
            Some("http://public.example/a/b?c=1")
        );
        // 未命中 → None（保持原值）
        assert!(apply_redirect(&rules, "https://other/x").is_none());

        // 正则 + 捕获
        let re = RedirectRule {
            m: MatchPattern::Regex(Regex::new(r"^http://(b\w+):\d+(/.*)$").unwrap()),
            replacement: "https://pub.example$2".into(),
        };
        assert_eq!(
            apply_redirect(&[re], "http://backend:9000/p/q").as_deref(),
            Some("https://pub.example/p/q")
        );

        // default 合成：上游 origin → 对外前缀（产出相对路径）
        let d = default_redirect_rule("http://10.0.0.5:8080/api/", "/v1/").unwrap();
        assert_eq!(apply_redirect(&[d], "http://10.0.0.5:8080/login").as_deref(), Some("/v1/login"));
    }

    #[test]
    fn public_prefix_and_origin_normalization() {
        assert_eq!(upstream_origin("http://a.b:8080/path"), Some("http://a.b:8080".to_string()));
        assert_eq!(upstream_origin("https://a.b"), Some("https://a.b".to_string()));
        assert_eq!(upstream_origin("grpc://a.b"), None);
        assert_eq!(public_prefix("/app"), "/app/");
        assert_eq!(public_prefix("/app/"), "/app/");
        assert_eq!(public_prefix("/"), "/");
        assert_eq!(public_prefix(""), "/");
    }

    #[test]
    fn cookie_domain_path_and_none() {
        let domain = CookieRewrite {
            off: false,
            rules: vec![CookieAttrRule {
                m: MatchPattern::Literal("backend.internal".into()),
                replacement: "public.example".into(),
                remove: false,
            }],
        };
        let path = CookieRewrite {
            off: false,
            rules: vec![CookieAttrRule {
                m: MatchPattern::Literal("/app".into()),
                replacement: "/gateway".into(),
                remove: false,
            }],
        };
        let cookie = "sid=xyz; domain=backend.internal; path=/app/sub; HttpOnly; Secure";
        let d1 = rewrite_cookie_attr(cookie, &domain, "domain");
        assert!(d1.contains("domain=public.example"), "{d1}");
        assert!(d1.contains("domain") && !d1.contains("backend.internal"), "{d1}");
        let p1 = rewrite_cookie_attr(&d1, &path, "path");
        assert!(p1.contains("path=/gateway/sub"), "{p1}");
        // 其它属性原样保留
        assert!(p1.contains("HttpOnly") && p1.contains("Secure"), "{p1}");
    }

    #[test]
    fn cookie_remove_with_none_and_regex_domain() {
        let rm = CookieRewrite {
            off: false,
            rules: vec![CookieAttrRule {
                m: MatchPattern::Literal("backend.internal".into()),
                replacement: "none".into(),
                remove: true,
            }],
        };
        let out = rewrite_cookie_attr("a=1; domain=backend.internal; path=/x", &rm, "domain");
        assert!(!out.contains("domain"), "{out}");
        assert!(out.contains("a=1") && out.contains("path=/x"), "{out}");

        let re = CookieAttrRule {
            m: MatchPattern::Regex(Regex::new(r"^\.?(b.*)\.internal$").unwrap()),
            replacement: "$1.example".into(),
            remove: false,
        };
        let cfg = CookieRewrite { off: false, rules: vec![re] };
        let out = rewrite_cookie_attr("a=1; domain=.backend.internal", &cfg, "domain");
        assert!(out.contains("domain=backend.example"), "{out}");
    }

    #[test]
    fn cookie_off_is_noop_and_domain_case_insensitive() {
        let cfg = CookieRewrite { off: true, rules: vec![CookieAttrRule {
            m: MatchPattern::Literal("x".into()), replacement: "y".into(), remove: false }] };
        assert_eq!(rewrite_cookie_attr("a=1; domain=x", &cfg, "domain"), "a=1; domain=x");

        let ci = CookieRewrite { off: false, rules: vec![CookieAttrRule {
            m: MatchPattern::Literal(".BACKEND.INTERNAL".into()), replacement: "pub".into(), remove: false }] };
        let out = rewrite_cookie_attr("a=1; domain=backend.internal", &ci, "domain");
        assert!(out.contains("domain=pub"), "{out}");
    }
}
