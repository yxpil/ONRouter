//! TLS 端点装配：多证书 SNI 解析 + ALPN + 协议版本控制。
//!
//! 一个监听端口上可以挂多张证书（来自多个 server 块），握手时按 ClientHello 的
//! server_name 选择：精确名 > `*.example.com` 通配 > 默认证书（第一个）。
//! 对应 nginx 的 `listen 443 ssl` + 多 server 块 + SNI 语义。

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::{
    ClientHello, NoServerSessionStorage, ProducesTickets, ResolvesServerCert,
    ServerSessionMemoryCache, StoresServerSessions,
};
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
    const ALL: [TlsVersion; 4] = [
        TlsVersion::Tls10,
        TlsVersion::Tls11,
        TlsVersion::Tls12,
        TlsVersion::Tls13,
    ];

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
    /// 会话恢复策略（`ssl_session_cache` / `ssl_session_tickets`）
    pub session: SessionOptions,
}

/// `ssl_session_cache` 的三种模式（nginx 语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCache {
    /// 不保存会话（nginx `off` / `none`）；若 tickets 开，仍可无状态恢复
    Off,
    /// 每个监听端口独立缓存，n 为会话条数（nginx `builtin[:n]`）
    Builtin(usize),
    /// 同名监听共享一个进程级缓存（nginx `shared:name:size`，size 按字节折算条数）
    Shared { name: String, capacity: usize },
}

impl Default for SessionCache {
    /// 保持既有行为：每监听 256 条，开箱即用可恢复。
    fn default() -> Self {
        SessionCache::Builtin(256)
    }
}

/// 一次构建内所有 TLS 监听共享的会话设施。
/// `shared_store` 和 `ticketer` 由 Router 构建时注入，使多端口行为与 nginx 的
/// shared 缓存 / 进程内 ticket 密钥一致（而不是每个监听各自一套）。
#[derive(Clone, Default)]
pub struct SessionOptions {
    pub cache: SessionCache,
    pub tickets: bool,
    pub shared_store: Option<Arc<dyn StoresServerSessions>>,
    pub ticketer: Option<Arc<dyn ProducesTickets>>,
}

impl fmt::Debug for SessionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionOptions")
            .field("cache", &self.cache)
            .field("tickets", &self.tickets)
            .field("shared_store", &self.shared_store.is_some())
            .field("ticketer", &self.ticketer.is_some())
            .finish()
    }
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
    let f =
        std::fs::File::open(path).map_err(|e| format!("打开证书 {} 失败: {e}", path.display()))?;
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
    let f =
        std::fs::File::open(path).map_err(|e| format!("打开私钥 {} 失败: {e}", path.display()))?;
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
        // 校验私钥与证书公钥匹配（rustls 在 CertifiedKey 使用时才报，这里提前失败）；
        // keys_match 同时会解析 X.509，损坏/伪造的 DER 在加载期就被拒绝，而不是拖到握手。
        let ck = Arc::new(CertifiedKey::new(certs, key));
        ck.keys_match().map_err(|e| {
            format!(
                "证书 {} 与私钥 {} 不匹配或证书无效: {e}",
                spec.cert.display(),
                spec.key.display()
            )
        })?;
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

/// ssl_certificate_by_lua 选出的固定证书：任何 SNI 都返回它（OpenResty set_cert 的语义——
/// 脚本显式指定后不再按 SNI 查表）。
#[derive(Debug)]
pub struct StaticResolver(pub Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// 解析 DER 私钥。脚本可能传 PKCS#8 / PKCS#1 / SEC1，逐个尝试比在 Lua 侧暴露格式差异更稳。
fn parse_der_key(der: Vec<u8>) -> Result<PrivateKeyDer<'static>, String> {
    let candidates = [
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.clone())),
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.clone())),
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
    ];
    for k in candidates {
        if any_supported_type(&k).is_ok() {
            return Ok(k);
        }
    }
    Err("私钥 DER 无法识别（支持 PKCS#8 / PKCS#1 / SEC1）".to_string())
}

/// ngx.ssl.set_cert_and_key 的落地点：DER 证书链 + DER 私钥 → CertifiedKey。
/// 同时校验私钥与首张证书匹配，让脚本里的错误在握手中立即暴露。
pub fn certified_key_from_der(
    cert_chain: Vec<Vec<u8>>,
    key_der: Vec<u8>,
) -> Result<CertifiedKey, String> {
    if cert_chain.is_empty() {
        return Err("证书链为空".to_string());
    }
    let certs: Vec<CertificateDer<'static>> = cert_chain
        .into_iter()
        .map(|d| CertificateDer::from(d).into_owned())
        .collect();
    let key = any_supported_type(&parse_der_key(key_der)?)
        .map_err(|e| format!("私钥不被支持的签名算法: {e}"))?;
    let ck = CertifiedKey::new(certs, key);
    ck.keys_match()
        .map_err(|e| format!("证书与私钥不匹配: {e}"))?;
    Ok(ck)
}

/// 动态证书缓存键：内容相同的一组证书/私钥共用同一份 ServerConfig（会话缓存也因此收敛）。
pub fn cert_pair_id(cert_chain: &[Vec<u8>], key_der: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    cert_chain.hash(&mut h);
    key_der.hash(&mut h);
    h.finish()
}

pub fn build_server_config(opts: &TlsOptions) -> Result<ServerConfig, String> {
    let resolver = Arc::new(build_resolver(&opts.specs)?);
    build_server_config_with(opts, resolver)
}

/// 入向 TLS 用哪套密钥交换组。默认（不开 `pq`）就是 rustls 的 ring provider：
/// `{X25519, P-256, P-384}`，与 1.0.3 及以前的行为逐字节一致。
///
/// 开 `pq` 后在 ring 的集合上**追加** `X25519MLKEM768`（`0x11ec`）：ring 里没有任何 ML-KEM
/// 实现，而真实世界里已经有 CDN 发来"只含后量子组"的 ClientHello（抓包证据与运维口径见
/// `docs/OPERATIONS.md` §5.6）。这里刻意只加一条组、不换 cipher/signer/随机源：
/// 其余仍然全部由 ring 提供，aws-lc 只贡献这一个 KX 实现。
fn kx_provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "pq")]
    {
        let mut p = rustls::crypto::ring::default_provider();
        p.kx_groups = {
            let mut g = p.kx_groups.clone();
            g.push(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768);
            g
        };
        Arc::new(p)
    }
    #[cfg(not(feature = "pq"))]
    Arc::new(rustls::crypto::ring::default_provider())
}

/// 用给定证书解析器装配其余 TLS 参数（协议集、ALPN、会话恢复）。
pub fn build_server_config_with(
    opts: &TlsOptions,
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<ServerConfig, String> {
    let protocols = opts.protocols.normalized();
    // rustls 只能协商 TLS1.2/1.3；1.0/1.1 由 feature-gated native 后端负责（见 build_native_acceptor）。
    let versions = protocols.rustls_versions();
    if versions.is_empty() {
        return Err(
            "ssl_protocols 只包含 TLSv1/TLSv1.1：内置 rustls 后端无法协商，请用 `--features native-tls` 重新构建"
                .to_string(),
        );
    }
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&kx_provider()))
        .with_protocol_versions(&versions)
        .map_err(|e| format!("TLS 参数组合不被当前 provider 支持: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = if opts.http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    // 会话恢复：off 明确用"永不存储"实现（默认 memory cache 会悄悄缓存）；
    // shared 必须由 Router 注入同一实例，才能跨监听端口恢复。
    config.session_storage = match &opts.session.cache {
        SessionCache::Off => Arc::new(NoServerSessionStorage {}),
        SessionCache::Builtin(cap) => ServerSessionMemoryCache::new((*cap).max(1)),
        SessionCache::Shared { .. } => match &opts.session.shared_store {
            Some(store) => Arc::clone(store),
            None => return Err("ssl_session_cache shared 缺少共享存储实例".to_string()),
        },
    };
    if opts.session.tickets {
        if let Some(t) = &opts.session.ticketer {
            config.ticketer = Arc::clone(t);
        }
    }
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
        let cert = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
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
        assert!(Arc::ptr_eq(
            &default,
            &resolver.choose(Some("spec.io")).unwrap()
        ));
        // 无 SNI / 未知 SNI 都用默认证书，而不是让握手失败
        assert!(Arc::ptr_eq(&default, &resolver.choose(None).unwrap()));
        assert!(Arc::ptr_eq(
            &default,
            &resolver.choose(Some("nope.net")).unwrap()
        ));
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
            session: SessionOptions::default(),
        })
        .unwrap();
        assert_eq!(
            h2.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        let h1 = build_server_config(&TlsOptions {
            specs: vec![spec],
            http2: false,
            protocols: TlsProtocols::from_min(TlsVersion::Tls13),
            session: SessionOptions::default(),
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
        let dir =
            std::env::temp_dir().join(format!("onrouter-certs-legacy-{}", std::process::id()));
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
            session: SessionOptions::default(),
        });
        assert!(
            err.is_err(),
            "仅 TLS1.0/1.1 时 rustls 后端应明确拒绝而非静默降级"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_cache_modes_and_ticketer_are_wired() {
        let dir =
            std::env::temp_dir().join(format!("onrouter-certs-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = write_pair(&dir, &["localhost"]);
        let spec = CertSpec {
            names: vec!["localhost".into()],
            cert: c,
            key: k,
        };

        let off = build_server_config(&TlsOptions {
            specs: vec![spec.clone()],
            http2: false,
            protocols: TlsProtocols::default(),
            session: SessionOptions {
                cache: SessionCache::Off,
                tickets: false,
                ..SessionOptions::default()
            },
        })
        .unwrap();
        assert!(!off.session_storage.can_cache(), "off 必须真正不缓存");
        assert!(!off.ticketer.enabled(), "tickets off 时不应签发 ticket");

        let shared: Arc<dyn StoresServerSessions> = ServerSessionMemoryCache::new(8);
        let ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        let cfg = build_server_config(&TlsOptions {
            specs: vec![spec.clone()],
            http2: false,
            protocols: TlsProtocols::default(),
            session: SessionOptions {
                cache: SessionCache::Shared {
                    name: "SSL".into(),
                    capacity: 8,
                },
                tickets: true,
                shared_store: Some(Arc::clone(&shared)),
                ticketer: Some(Arc::clone(&ticketer)),
            },
        })
        .unwrap();
        assert!(cfg.session_storage.can_cache());
        assert!(
            Arc::ptr_eq(&cfg.session_storage, &shared),
            "shared 模式必须复用注入的同一缓存实例"
        );
        assert!(Arc::ptr_eq(&cfg.ticketer, &ticketer));
        assert!(cfg.ticketer.enabled());

        let missing = build_server_config(&TlsOptions {
            specs: vec![spec],
            http2: false,
            protocols: TlsProtocols::default(),
            session: SessionOptions {
                cache: SessionCache::Shared {
                    name: "SSL".into(),
                    capacity: 8,
                },
                ..SessionOptions::default()
            },
        });
        assert!(missing.is_err(), "shared 模式未注入存储时应明确报错");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dynamic_certified_key_from_der_validates_pairing() {
        let pair = rcgen::generate_simple_self_signed(vec!["dyn.test".into()]).unwrap();
        let chain = vec![pair.cert.der().as_ref().to_vec()];
        let key = pair.key_pair.serialize_der();
        let ck = certified_key_from_der(chain.clone(), key.clone()).expect("合法证书对");
        assert_eq!(ck.cert.len(), 1);

        // 同一证书配另一把私钥 -> 拒绝（keys_match 校验）
        let other = rcgen::generate_simple_self_signed(vec!["dyn.test".into()]).unwrap();
        assert!(
            certified_key_from_der(chain.clone(), other.key_pair.serialize_der()).is_err(),
            "私钥错配必须被拒绝"
        );
        assert!(
            certified_key_from_der(Vec::new(), key.clone()).is_err(),
            "空证书链必须拒绝"
        );
        // 缓存键随内容变化
        assert_ne!(cert_pair_id(&chain, &key), cert_pair_id(&chain, b"other"));
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
