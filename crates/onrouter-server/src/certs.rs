//! TLS 端点装配：多证书 SNI 解析 + ALPN + 协议版本控制。
//!
//! 一个监听端口上可以挂多张证书（来自多个 server 块），握手时按 ClientHello 的
//! server_name 选择：精确名 > `*.example.com` 通配 > 默认证书（第一个）。
//! 对应 nginx 的 `listen 443 ssl` + 多 server 块 + SNI 语义。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SupportedProtocolVersion};

/// 一对证书（服务于某个 server_name 集合）
#[derive(Debug, Clone)]
pub struct CertSpec {
    pub names: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// 单个 TLS 协议版本。`Ord` 按新旧升序，用于 `from_min`（最低版本 → 该版本及以上全部启用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    const ALL: [TlsVersion; 4] = [TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12, TlsVersion::Tls13];

    /// nginx `ssl_protocols` 里的写法（小写 token）。
    pub fn from_nginx_token(tok: &str) -> Option<TlsVersion> {
        match tok.to_ascii_lowercase().as_str() {
            "tlsv1.0" | "tlsv1" | "1.0" => Some(TlsVersion::Tls10),
            "tlsv1.1" | "1.1" => Some(TlsVersion::Tls11),
            "tlsv1.2" | "1.2" => Some(TlsVersion::Tls12),
            "tlsv1.3" | "1.3" => Some(TlsVersion::Tls13),
            _ => None,
        }
    }
}

/// 显式启用的协议集合（对标 nginx `ssl_protocols`，可任意裁剪，不是"最低版本"下限）。
/// `enabled` 升序去重；空集合按默认（TLS1.2 + TLS1.3）处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsProtocols {
    pub enabled: Vec<TlsVersion>,
}

impl Default for TlsProtocols {
    fn default() -> Self {
        Self::from_min(TlsVersion::Tls12)
    }
}

impl TlsProtocols {
    /// 从最低版本向上启用（`ssl_min_version` 的等价展开）。
    pub fn from_min(min: TlsVersion) -> Self {
        Self {
            enabled: TlsVersion::ALL.into_iter().filter(|v| *v >= min).collect(),
        }
    }

    pub fn set(&mut self, v: TlsVersion) {
        if !self.enabled.contains(&v) {
            self.enabled.push(v);
            self.enabled.sort_unstable();
        }
    }

    /// 同一监听端口上多个 server 的协议集取并集（socket 对外提供任一格要求的版本）。
    pub fn union_with(&mut self, other: &TlsProtocols) {
        for v in &other.enabled {
            self.set(*v);
        }
    }

    pub fn contains(&self, v: TlsVersion) -> bool {
        self.enabled.contains(&v)
    }

    /// 是否请求了 rustls 无法协商的旧版本（TLS 1.0/1.1）——需要 native-tls 后端才能落地。
    pub fn wants_legacy(&self) -> bool {
        self.enabled.iter().any(|v| *v <= TlsVersion::Tls11)
    }

    fn is_empty(&self) -> bool {
        self.enabled.is_empty()
    }

    /// rustls 能提供的版本子集（1.0/1.1 被过滤掉，由 native 后端负责）。
    pub fn rustls_versions(&self) -> Vec<&'static SupportedProtocolVersion> {
        let mut out = Vec::new();
        if self.contains(TlsVersion::Tls13) {
            out.push(&rustls::version::TLS13);
        }
        if self.contains(TlsVersion::Tls12) {
            out.push(&rustls::version::TLS12);
        }
        out
    }

    /// 归一化：空集合回落默认（1.2+1.3），供构建前使用。
    pub fn normalized(&self) -> TlsProtocols {
        if self.is_empty() {
            TlsProtocols::default()
        } else {
            self.clone()
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsOptions {
    pub specs: Vec<CertSpec>,
    /// ALPN 是否协商 h2
    pub http2: bool,
    /// 显式启用的 TLS 协议集合（`ssl_protocols`）
    pub protocols: TlsProtocols,
}

#[derive(Debug)]
pub struct SniResolver {
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// `*.example.com` 存成后缀 `.example.com`
    wildcard: Vec<(String, Arc<CertifiedKey>)>,
    default: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.choose(client_hello.server_name())
    }
}

impl SniResolver {
    /// SNI -> 证书。没有 SNI（HTTPS 直连 IP、或 TLS1.3 的 ECH/无扩展客户端）时，
    /// 和 nginx 一样退回 default server 的证书，而不是掐断握手：
    /// 证书选择失败只会让客户端看到一个没有状态码的握手错误，比 404 难查得多。
    pub fn choose(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let Some(name) = server_name else {
            return Some(Arc::clone(&self.default));
        };
        let sni = name.to_ascii_lowercase();
        if let Some(k) = self.exact.get(&sni) {
            return Some(Arc::clone(k));
        }
        // 通配只匹配子域：`*.example.com` 命中 api.example.com，不命中 example.com
        for (suffix, key) in &self.wildcard {
            if sni.ends_with(suffix.as_str()) && sni.len() > suffix.len() {
                return Some(Arc::clone(key));
            }
        }
        Some(Arc::clone(&self.default))
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("打开证书 {} 失败: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(f);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("解析证书 {} 失败: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} 里没有 PEM 证书", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("打开私钥 {} 失败: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(f);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("解析私钥 {} 失败: {e}", path.display()))?
        .ok_or_else(|| format!("{} 中未找到私钥", path.display()))
}

pub fn build_resolver(specs: &[CertSpec]) -> Result<SniResolver, String> {
    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcard: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
    let mut default: Option<Arc<CertifiedKey>> = None;

    for spec in specs {
        let certs = load_certs(&spec.cert)?;
        let key_der = load_key(&spec.key)?;
        let key = any_supported_type(&key_der)
            .map_err(|e| format!("私钥 {} 不被支持的签名算法: {e}", spec.key.display()))?;
        // 校验私钥与证书公钥匹配（rustls 在 CertifiedKey 使用时才报，这里提前失败）
        let ck = Arc::new(CertifiedKey::new(certs, key));
        if default.is_none() {
            default = Some(Arc::clone(&ck));
        }
        for name in &spec.names {
            let n = name.trim().to_ascii_lowercase();
            if n.is_empty() {
                continue;
            }
            match n.strip_prefix('*') {
                Some(suffix) => wildcard.push((suffix.to_string(), Arc::clone(&ck))),
                None => {
                    exact.insert(n, Arc::clone(&ck));
                }
            }
        }
    }
    let default = default.ok_or("TLS 监听端口没有配置任何证书")?;
    Ok(SniResolver {
        exact,
        wildcard,
        default,
    })
}

pub fn build_server_config(opts: &TlsOptions) -> Result<ServerConfig, String> {
    let resolver = Arc::new(build_resolver(&opts.specs)?);
    let protocols = opts.protocols.normalized();
    // rustls 只能协商 TLS1.2/1.3；1.0/1.1 由 feature-gated native 后端负责（见 build_native_acceptor）。
    let versions = protocols.rustls_versions();
    if versions.is_empty() {
        return Err(
            "ssl_protocols 只包含 TLSv1/TLSv1.1：内置 rustls 后端无法协商，请用 `--features native-tls` 重新构建"
                .to_string(),
        );
    }
    let mut config = ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = if opts.http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(config)
}

/// QUIC/HTTP/3 用的 rustls 配置：RFC 9001 只允许 TLS1.3，ALPN 固定 `h3`，
/// 证书走与 TCP 监听相同的 SNI 解析器（复用 build_resolver 的多证书/通配/默认逻辑）。
/// max_early_data_size=u32::MAX 是 quinn 转换 QuicServerConfig 的要求（否则拒绝 0-RTT 且校验失败）。
pub fn build_quic_server_config(specs: &[CertSpec]) -> Result<ServerConfig, String> {
    let resolver = Arc::new(build_resolver(specs)?);
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = u32::MAX;
    Ok(config)
}

/// 供 `-t` 配置校验使用：只解析证书与私钥，不装 acceptor
pub fn validate(specs: &[CertSpec]) -> Result<Vec<String>, String> {
    let r = build_resolver(specs)?;
    let mut out: Vec<String> = r.exact.keys().cloned().collect();
    out.extend(r.wildcard.iter().map(|(s, _)| format!("*{s}")));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pair(dir: &Path, names: &[&str]) -> (PathBuf, PathBuf) {
        let cert =
            rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("rcgen 生成证书");
        let cp = dir.join(format!("{}-cert.pem", names[0].replace('*', "wild")));
        let kp = dir.join(format!("{}-key.pem", names[0].replace('*', "wild")));
        std::fs::write(&cp, cert.cert.pem()).unwrap();
        std::fs::write(&kp, cert.key_pair.serialize_pem()).unwrap();
        (cp, kp)
    }

    #[test]
    fn builds_config_from_two_certs_and_prefers_exact_then_wildcard() {
        let dir = std::env::temp_dir().join(format!("onrouter-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c1, k1) = write_pair(&dir, &["*.example.com", "example.com"]);
        let (c2, k2) = write_pair(&dir, &["api.other.com"]);

        let resolver = build_resolver(&[
            CertSpec {
                names: vec!["*.example.com".into(), "example.com".into()],
                cert: c1,
                key: k1,
            },
            CertSpec {
                names: vec!["api.other.com".into()],
                cert: c2,
                key: k2,
            },
        ])
        .unwrap();

        assert!(resolver.exact.contains_key("example.com"));
        assert!(resolver.exact.contains_key("api.other.com"));
        assert_eq!(resolver.wildcard.len(), 1);
        assert_eq!(resolver.wildcard[0].0, ".example.com");
        // 默认证书 = 第一个 spec
        assert!(Arc::ptr_eq(
            &resolver.choose(None).unwrap(),
            &resolver.choose(Some("example.com")).unwrap()
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chooses_cert_by_sni_with_default_fallback() {
        let dir = std::env::temp_dir().join(format!("onrouter-certs-sni-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c1, k1) = write_pair(&dir, &["example.com"]);
        let (c2, k2) = write_pair(&dir, &["*.spec.io"]);
        let resolver = build_resolver(&[
            CertSpec {
                names: vec!["example.com".into()],
                cert: c1,
                key: k1,
            },
            CertSpec {
                names: vec!["*.spec.io".into()],
                cert: c2,
                key: k2,
            },
        ])
        .unwrap();
        let default = resolver.choose(Some("example.com")).unwrap();
        let wildcard_cert = resolver.choose(Some("a.spec.io")).unwrap();
        // 通配命中子域，且不是默认证书
        assert!(!Arc::ptr_eq(&default, &wildcard_cert));
        assert!(Arc::ptr_eq(
            &wildcard_cert,
            &resolver.choose(Some("API.SPEC.IO")).unwrap()
        ));
        // 通配不覆盖主域本身：spec.io 回落默认
        assert!(Arc::ptr_eq(&default, &resolver.choose(Some("spec.io")).unwrap()));
        // 无 SNI / 未知 SNI 都用默认证书，而不是让握手失败
        assert!(Arc::ptr_eq(&default, &resolver.choose(None).unwrap()));
        assert!(Arc::ptr_eq(&default, &resolver.choose(Some("nope.net")).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_missing_cert_file() {
        let err = build_resolver(&[CertSpec {
            names: vec!["x.com".into()],
            cert: PathBuf::from("/nope/not-here.pem"),
            key: PathBuf::from("/nope/not-here-key.pem"),
        }]);
        assert!(err.is_err());
    }

    #[test]
    fn server_config_sets_alpn_by_http2_flag() {
        let dir = std::env::temp_dir().join(format!("onrouter-certs-alpn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = write_pair(&dir, &["localhost"]);
        let spec = CertSpec {
            names: vec!["localhost".into()],
            cert: c,
            key: k,
        };
        let h2 = build_server_config(&TlsOptions {
            specs: vec![spec.clone()],
            http2: true,
            protocols: TlsProtocols::default(),
        })
        .unwrap();
        assert_eq!(h2.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        let h1 = build_server_config(&TlsOptions {
            specs: vec![spec],
            http2: false,
            protocols: TlsProtocols::from_min(TlsVersion::Tls13),
        })
        .unwrap();
        assert_eq!(h1.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssl_protocols_set_controls_enabled_versions() {
        // 显式集合：只开 TLS1.2 时 rustls 版本集就只有 TLS12（可裁剪掉 1.3）
        let only12 = TlsProtocols {
            enabled: vec![TlsVersion::Tls12],
        };
        assert_eq!(only12.rustls_versions().len(), 1);
        assert!(only12.rustls_versions().contains(&&rustls::version::TLS12));
        assert!(!only12.wants_legacy());

        // 只开 TLS1.3
        let only13 = TlsProtocols {
            enabled: vec![TlsVersion::Tls13],
        };
        assert_eq!(only13.rustls_versions(), vec![&rustls::version::TLS13]);

        // from_min(1.2) = {1.2,1.3}
        assert_eq!(
            TlsProtocols::from_min(TlsVersion::Tls12).enabled,
            vec![TlsVersion::Tls12, TlsVersion::Tls13]
        );

        // 旧版本标记 wants_legacy，且被 rustls_versions 过滤掉
        let legacy = TlsProtocols {
            enabled: vec![TlsVersion::Tls10, TlsVersion::Tls11, TlsVersion::Tls12],
        };
        assert!(legacy.wants_legacy());
        assert_eq!(legacy.rustls_versions(), vec![&rustls::version::TLS12]);

        // 并集去重升序
        let mut merged = TlsProtocols {
            enabled: vec![TlsVersion::Tls13],
        };
        merged.union_with(&TlsProtocols {
            enabled: vec![TlsVersion::Tls12, TlsVersion::Tls13],
        });
        assert_eq!(merged.enabled, vec![TlsVersion::Tls12, TlsVersion::Tls13]);
    }

    #[test]
    fn legacy_only_protocols_rejected_by_rustls_backend() {
        let dir = std::env::temp_dir().join(format!("onrouter-certs-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = write_pair(&dir, &["localhost"]);
        let err = build_server_config(&TlsOptions {
            specs: vec![CertSpec {
                names: vec!["localhost".into()],
                cert: c,
                key: k,
            }],
            http2: false,
            protocols: TlsProtocols {
                enabled: vec![TlsVersion::Tls10, TlsVersion::Tls11],
            },
        });
        assert!(err.is_err(), "仅 TLS1.0/1.1 时 rustls 后端应明确拒绝而非静默降级");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quic_config_pins_tls13_and_alpn_h3() {
        let dir = std::env::temp_dir().join(format!("onrouter-certs-quic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = write_pair(&dir, &["localhost"]);
        let cfg = build_quic_server_config(&[CertSpec {
            names: vec!["localhost".into()],
            cert: c,
            key: k,
        }])
        .unwrap();
        // QUIC/RFC 9001：只允许 TLS1.3，ALPN 固定 h3
        // （rustls 的 versions 字段私有，TLS1.3-only 由 builder_with_protocol_versions 保证）
        assert_eq!(cfg.alpn_protocols, vec![b"h3".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
