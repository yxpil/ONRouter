//! 服务器侧 TLS 抽象：默认走纯 Rust 的 rustls（TLS1.2/1.3 + SNI 多证书 + ALPN h2），
//! 在 `native-tls` feature 开启且监听显式请求旧协议（TLSv1/TLSv1.1）时，改走平台原生
//! 后端（Windows=Schannel，Linux/macOS=系统 TLS 栈）——rustls 本身拒绝协商这两个版本，
//! 只有原生栈能提供，用于遗留客户端/兼容性。
//!
//! 配置了 `ssl_certificate_by_lua*` 时，rustls 路径改用 `LazyConfigAcceptor`：先读到
//! ClientHello（可取 SNI），执行 Lua 决定证书或中止握手，再继续 TLS 握手。没有脚本时
//! 仍走原来的直接 accept 快路径，不引入额外往返。
//!
//! 两条路径握手后统一成 `ServerStream`（实现 AsyncRead/AsyncWrite），因此上层 hyper 的
//! h1/h2 服务循环 `server::drive` 完全无需分支——与 HTTP/3 复用同一请求核的思路一致。

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::LazyConfigAcceptor;

use crate::certs::{self, TlsOptions};
use crate::engine::{RequestCtx, SslState};
use crate::lua_engine::LuaEngine;
use crate::router::SslCertScript;

/// ssl_certificate_by_lua 动态证书的 ServerConfig 缓存上限。证书通常按 SNI/租户固定，
/// 少量条目即可命中；脚本每次生成全新证书时清空重来，避免无界增长。
const DYNAMIC_CONFIG_CACHE_MAX: usize = 64;

/// 统一的服务端 TLS 接受器。`Clone` 以便每连接复制。
#[derive(Clone)]
pub struct TlsAcceptor {
    kind: AcceptorKind,
}

#[derive(Clone)]
enum AcceptorKind {
    Rustls(Arc<RustlsAcceptor>),
    #[cfg(feature = "native-tls")]
    Native(Arc<tokio_native_tls::TlsAcceptor>),
}

struct RustlsAcceptor {
    /// 静态证书配置（无脚本，或脚本未改证书时使用）
    base: Arc<rustls::ServerConfig>,
    /// 动态配置的模板参数（协议集/ALPN/会话缓存）
    opts: TlsOptions,
    lua: Arc<LuaEngine>,
    scripts: Vec<SslCertScript>,
    dynamic: Mutex<HashMap<u64, Arc<rustls::ServerConfig>>>,
}

/// 握手后的统一 TLS 流。
pub enum ServerStream {
    Rustls(tokio_rustls::server::TlsStream<TcpStream>),
    #[cfg(feature = "native-tls")]
    Native(Box<tokio_native_tls::TlsStream<TcpStream>>),
}

impl AsyncRead for ServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerStream::Rustls(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "native-tls")]
            ServerStream::Native(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ServerStream::Rustls(s) => Pin::new(s).poll_write(cx, data),
            #[cfg(feature = "native-tls")]
            ServerStream::Native(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerStream::Rustls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "native-tls")]
            ServerStream::Native(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ServerStream::Rustls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "native-tls")]
            ServerStream::Native(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn alpn_is_h2(s: &tokio_rustls::server::TlsStream<TcpStream>) -> bool {
    s.get_ref()
        .1
        .alpn_protocol()
        .map(|p| p == b"h2")
        .unwrap_or(false)
}

/// 按 SNI 选 server 块的脚本：精确名 > `*.suffix` 通配 > 首个（默认 server）。
/// 没有 SNI 时和 nginx 一样落到默认 server。
fn select_script<'a>(scripts: &'a [SslCertScript], sni: Option<&str>) -> Option<&'a SslCertScript> {
    let Some(sni) = sni.map(|s| s.to_ascii_lowercase()) else {
        return scripts.first();
    };
    if let Some(s) = scripts
        .iter()
        .find(|s| s.names.iter().any(|n| n.eq_ignore_ascii_case(&sni)))
    {
        return Some(s);
    }
    if let Some(s) = scripts.iter().find(|s| {
        s.names.iter().any(|n| match n.strip_prefix('*') {
            Some(suffix) => sni.ends_with(suffix) && sni.len() > suffix.len(),
            None => false,
        })
    }) {
        return Some(s);
    }
    scripts.first()
}

impl RustlsAcceptor {
    /// 执行握手脚本并产出用于后续握手的配置。脚本不设置证书时沿用静态 SNI 配置。
    async fn config_for(
        &self,
        script: &SslCertScript,
        sni: Option<&str>,
    ) -> Result<Arc<rustls::ServerConfig>, String> {
        let mut ctx = RequestCtx::detached();
        ctx.ssl = Some(SslState {
            server_name: sni.map(|s| s.to_ascii_lowercase()),
            ..SslState::default()
        });
        let shared = Arc::new(Mutex::new(ctx));
        if let Err(e) = self
            .lua
            .run_phase("ssl_certificate", &script.source, Arc::clone(&shared))
            .await
        {
            return Err(format!("{} 执行失败: {e}", script.directive));
        }
        let state = shared.lock().unwrap().ssl.take().unwrap_or_default();
        if state.aborted {
            return Err(format!(
                "{} 中止握手（ngx.exit 传入错误码）",
                script.directive
            ));
        }
        match (state.cert_chain, state.priv_key) {
            (Some(chain), Some(key)) => {
                let id = certs::cert_pair_id(&chain, &key);
                if let Some(cfg) = self.dynamic.lock().unwrap().get(&id) {
                    return Ok(Arc::clone(cfg));
                }
                let ck = certs::certified_key_from_der(chain, key)
                    .map_err(|e| format!("{} 设置的证书无效: {e}", script.directive))?;
                let resolver = Arc::new(certs::StaticResolver(Arc::new(ck)));
                let cfg = Arc::new(certs::build_server_config_with(&self.opts, resolver)?);
                let mut cache = self.dynamic.lock().unwrap();
                if cache.len() >= DYNAMIC_CONFIG_CACHE_MAX {
                    cache.clear();
                }
                cache.insert(id, Arc::clone(&cfg));
                Ok(cfg)
            }
            (None, None) if state.cleared => Err(format!(
                "{} 调用 clear_certs() 后没有设置新证书",
                script.directive
            )),
            (None, None) => Ok(Arc::clone(&self.base)),
            (cert, _) => Err(format!(
                "{} 只设置了{}：证书与私钥必须成对",
                script.directive,
                if cert.is_some() { "证书" } else { "私钥" }
            )),
        }
    }

    async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<(ServerStream, bool), Box<dyn std::error::Error + Send + Sync>> {
        if self.scripts.is_empty() {
            let s = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.base))
                .accept(stream)
                .await?;
            let h2 = alpn_is_h2(&s);
            return Ok((ServerStream::Rustls(s), h2));
        }

        // 先只解析 ClientHello，拿到 SNI 后再决定用哪套证书配置继续握手
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
        let sni = start.client_hello().server_name().map(|s| s.to_string());
        let cfg = match select_script(&self.scripts, sni.as_deref()) {
            Some(script) => match self.config_for(script, sni.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    crate::log_warn!("TLS 握手脚本失败（SNI {:?}，{e}）", sni);
                    return Err(io::Error::other(e).into());
                }
            },
            None => Arc::clone(&self.base),
        };
        let s = start.into_stream(cfg).await?;
        let h2 = alpn_is_h2(&s);
        Ok((ServerStream::Rustls(s), h2))
    }
}

/// 握手结果附带这条连接是否协商到 h2（原生 legacy 后端固定 HTTP/1.1，返回 false）。
impl TlsAcceptor {
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<(ServerStream, bool), Box<dyn std::error::Error + Send + Sync>> {
        match &self.kind {
            AcceptorKind::Rustls(a) => a.accept(stream).await,
            #[cfg(feature = "native-tls")]
            AcceptorKind::Native(a) => {
                // legacy 后端只服务 HTTP/1.1（h2/h2c 与 TLS1.0/1.1 不配对）
                let s = a.accept(stream).await?;
                Ok((ServerStream::Native(Box::new(s)), false))
            }
        }
    }
}

/// 依据 `ssl_protocols` 选择后端：请求了旧协议且编译了原生 feature → 原生；否则 rustls。
pub fn make_acceptor(
    opts: &TlsOptions,
    scripts: &[SslCertScript],
    lua: Arc<LuaEngine>,
) -> Result<TlsAcceptor, String> {
    #[cfg(feature = "native-tls")]
    if opts.protocols.wants_legacy() {
        if !scripts.is_empty() {
            crate::log_warn!(
                "native-tls 后端（TLSv1/TLSv1.1）不支持 ssl_certificate_by_lua，{} 个握手脚本将被忽略",
                scripts.len()
            );
        }
        crate::log_info!(
            "TLS 走平台原生后端（native-tls）以协商旧协议：启用集合 {:?}",
            opts.protocols.normalized().enabled
        );
        return build_native(opts).map(|a| TlsAcceptor {
            kind: AcceptorKind::Native(Arc::new(a)),
        });
    }
    #[cfg(not(feature = "native-tls"))]
    if opts.protocols.wants_legacy() {
        crate::log_warn!(
            "ssl_protocols 含 TLSv1/TLSv1.1，但本次构建未启用 `--features native-tls`：这些旧版本将被忽略，仅提供 TLS1.2/1.3"
        );
    }
    let cfg = certs::build_server_config(opts)?;
    if !scripts.is_empty() {
        crate::log_info!(
            "ssl_certificate_by_lua 已启用：{} 个 server 脚本参与握手证书选择",
            scripts.len()
        );
    }
    Ok(TlsAcceptor {
        kind: AcceptorKind::Rustls(Arc::new(RustlsAcceptor {
            base: Arc::new(cfg),
            opts: opts.clone(),
            lua,
            scripts: scripts.to_vec(),
            dynamic: Mutex::new(HashMap::new()),
        })),
    })
}

/// 所有 TLS 证书/私钥文件（去重）。重载任务监视这些文件的 mtime/大小，
/// 使证书原地续期（配置文件不变）也能触发一次热刷新。
pub fn cert_files(listeners: &[crate::router::Listener]) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    for l in listeners {
        if let Some(opts) = &l.tls {
            for s in &opts.specs {
                for p in [&s.cert, &s.key] {
                    if !out.contains(p) {
                        out.push(p.clone());
                    }
                }
            }
        }
    }
    out
}

/// QUIC/TLS 服务端配置构造（启动与热重载共用，保证两条路径参数一致）。
pub fn make_quic_server_config(
    opts: &TlsOptions,
    max_concurrent_streams: u32,
) -> Result<quinn::ServerConfig, String> {
    let cfg = certs::build_quic_server_config(&opts.specs)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(cfg)
        .map_err(|e| format!("QUIC 无法装载 TLS 配置: {e:?}"))?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(max_concurrent_streams));
    server_cfg.transport_config(Arc::new(transport));
    Ok(server_cfg)
}

/// 运行期 TLS 注册表：监听地址 → 当前接受器 / QUIC endpoint。
/// 热重载重建后原地替换；accept 循环每连接取一次句柄，在途连接继续用旧配置跑完。
#[derive(Default)]
pub struct TlsRegistry {
    tcp: RwLock<HashMap<SocketAddr, TlsAcceptor>>,
    quic: Mutex<HashMap<SocketAddr, quinn::Endpoint>>,
}

impl TlsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_tcp(&self, addr: SocketAddr, acceptor: TlsAcceptor) {
        self.tcp
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(addr, acceptor);
    }

    pub fn tcp(&self, addr: SocketAddr) -> Option<TlsAcceptor> {
        self.tcp
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&addr)
            .cloned()
    }

    pub fn register_quic(&self, addr: SocketAddr, endpoint: quinn::Endpoint) {
        self.quic
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(addr, endpoint);
    }

    /// 按新配置刷新证书 / 协议 / 握手脚本 / QUIC 服务端配置。
    /// 重活（读证书、建配置）在锁外完成；单个监听失败只记日志并保留旧配置。
    /// 明文↔TLS 或新增 QUIC 端点的切换无法在运行期完成（需重启）。
    pub fn reload(&self, fresh: &[crate::router::Listener], lua: Arc<LuaEngine>, max_streams: u32) {
        let known_tcp: std::collections::HashSet<SocketAddr> = self
            .tcp
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();
        let known_quic: std::collections::HashSet<SocketAddr> = self
            .quic
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .copied()
            .collect();

        let mut tcp_updates = Vec::new();
        let mut quic_updates = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for l in fresh {
            let Some(opts) = &l.tls else { continue };
            seen.insert(l.addr);
            if known_tcp.contains(&l.addr) {
                match make_acceptor(opts, &l.ssl_cert_scripts, Arc::clone(&lua)) {
                    Ok(acc) => tcp_updates.push((l.addr, acc)),
                    Err(e) => crate::log_error!("{} TLS 热刷新失败，继续使用旧配置: {e}", l.addr),
                }
            } else {
                crate::log_warn!(
                    "{} 启动时是明文监听，新配置要求 TLS：需重启才能切换（本次跳过）",
                    l.addr
                );
            }
            if l.quic {
                if known_quic.contains(&l.addr) {
                    match make_quic_server_config(opts, max_streams) {
                        Ok(cfg) => quic_updates.push((l.addr, cfg)),
                        Err(e) => {
                            crate::log_error!("{} QUIC 热刷新失败，继续使用旧配置: {e}", l.addr)
                        }
                    }
                } else {
                    crate::log_warn!("{} 新增的 QUIC 监听无法在运行期绑定：需重启", l.addr);
                }
            }
        }

        if !tcp_updates.is_empty() {
            let mut tcp = self.tcp.write().unwrap_or_else(|p| p.into_inner());
            for (addr, acc) in tcp_updates {
                tcp.insert(addr, acc);
                crate::log_info!("{addr} TLS 已热刷新（证书 / 协议 / 握手脚本）");
            }
        }
        if !quic_updates.is_empty() {
            let quic = self.quic.lock().unwrap_or_else(|p| p.into_inner());
            for (addr, cfg) in quic_updates {
                if let Some(ep) = quic.get(&addr) {
                    ep.set_server_config(Some(cfg));
                    crate::log_info!("{addr} QUIC 证书已热刷新");
                }
            }
        }
        for addr in known_tcp {
            if !seen.contains(&addr) {
                crate::log_warn!(
                    "{addr} 新配置不再以 TLS 提供服务（或已移除该监听）：运行中的监听保持原样，需重启生效"
                );
            }
        }
    }
}

/// 原生后端接受器：取默认证书（无 SNI 多证书），按启用集合钉死 min/max 协议版本。
#[cfg(feature = "native-tls")]
fn build_native(opts: &TlsOptions) -> Result<tokio_native_tls::TlsAcceptor, String> {
    use native_tls::{Identity, TlsAcceptor as NtAcceptor};

    let spec = opts
        .specs
        .first()
        .ok_or("native TLS：该监听没有配置任何证书")?;
    let cert = std::fs::read(&spec.cert)
        .map_err(|e| format!("读取证书 {} 失败: {e}", spec.cert.display()))?;
    let key = std::fs::read(&spec.key)
        .map_err(|e| format!("读取私钥 {} 失败: {e}", spec.key.display()))?;
    let identity = Identity::from_pkcs8(&cert, &key)
        .map_err(|e| format!("native-tls 载入证书/私钥失败（需 PKCS8 PEM）: {e}"))?;

    let protocols = opts.protocols.normalized();
    let min = to_native_proto(*protocols.enabled.first().unwrap());
    let max = to_native_proto(*protocols.enabled.last().unwrap());

    let mut b = NtAcceptor::builder(identity);
    b.min_protocol_version(Some(min));
    b.max_protocol_version(Some(max));
    // legacy 后端不做 ALPN（TLS1.0/1.1 上不会有 h2），恒为 HTTP/1.1
    let acc = b
        .build()
        .map_err(|e| format!("native-tls TlsAcceptor 构建失败: {e}"))?;
    Ok(acc.into())
}

#[cfg(feature = "native-tls")]
fn to_native_proto(v: crate::certs::TlsVersion) -> native_tls::Protocol {
    use crate::certs::TlsVersion;
    match v {
        TlsVersion::Tls10 => native_tls::Protocol::Tlsv10,
        TlsVersion::Tls11 => native_tls::Protocol::Tlsv11,
        TlsVersion::Tls12 => native_tls::Protocol::Tlsv12,
        TlsVersion::Tls13 => native_tls::Protocol::Tlsv13,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lua_engine::LuaSource;

    fn script(names: &[&str]) -> SslCertScript {
        SslCertScript {
            names: names.iter().map(|s| s.to_string()).collect(),
            directive: "ssl_certificate_by_lua".into(),
            source: LuaSource::Inline(Arc::from("")),
        }
    }

    #[test]
    fn select_script_prefers_exact_then_wildcard_then_default() {
        let scripts = vec![script(&["default.test"]), script(&["*.wild.test"])];
        assert_eq!(
            select_script(&scripts, Some("DEFAULT.test")).unwrap().names[0],
            "default.test"
        );
        assert_eq!(
            select_script(&scripts, Some("a.WILD.test")).unwrap().names[0],
            "*.wild.test"
        );
        // 未知 SNI / 无 SNI 都落到首个（默认 server），不会让握手失败
        assert_eq!(
            select_script(&scripts, Some("nope.test")).unwrap().names[0],
            "default.test"
        );
        assert_eq!(
            select_script(&scripts, None).unwrap().names[0],
            "default.test"
        );
        assert!(select_script(&[], Some("x.test")).is_none());
    }
}
