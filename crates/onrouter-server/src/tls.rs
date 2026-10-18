//! 服务器侧 TLS 抽象：默认走纯 Rust 的 rustls（TLS1.2/1.3 + SNI 多证书 + ALPN h2），
//! 在 `native-tls` feature 开启且监听显式请求旧协议（TLSv1/TLSv1.1）时，改走平台原生
//! 后端（Windows=Schannel，Linux/macOS=系统 TLS 栈）——rustls 本身拒绝协商这两个版本，
//! 只有原生栈能提供，用于遗留客户端/兼容性。
//!
//! 两条路径握手后统一成 `ServerStream`（实现 AsyncRead/AsyncWrite），因此上层 hyper 的
//! h1/h2 服务循环 `server::drive` 完全无需分支——与 HTTP/3 复用同一请求核的思路一致。

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::certs::{self, TlsOptions};

/// 统一的服务端 TLS 接受器。`Clone` 以便每连接复制。
#[derive(Clone)]
pub enum TlsAcceptor {
    Rustls(tokio_rustls::TlsAcceptor),
    #[cfg(feature = "native-tls")]
    Native(Arc<tokio_native_tls::TlsAcceptor>),
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

/// 握手结果附带这条连接是否协商到 h2（原生 legacy 后端固定 HTTP/1.1，返回 false）。
impl TlsAcceptor {
    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> Result<(ServerStream, bool), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            TlsAcceptor::Rustls(a) => {
                let s = a.accept(stream).await?;
                let h2 = s
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| p == b"h2")
                    .unwrap_or(false);
                Ok((ServerStream::Rustls(s), h2))
            }
            #[cfg(feature = "native-tls")]
            TlsAcceptor::Native(a) => {
                // legacy 后端只服务 HTTP/1.1（h2/h2c 与 TLS1.0/1.1 不配对）
                let s = a.accept(stream).await?;
                Ok((ServerStream::Native(Box::new(s)), false))
            }
        }
    }
}

/// 依据 `ssl_protocols` 选择后端：请求了旧协议且编译了原生 feature → 原生；否则 rustls。
pub fn make_acceptor(opts: &TlsOptions) -> Result<TlsAcceptor, String> {
    #[cfg(feature = "native-tls")]
    if opts.protocols.wants_legacy() {
        crate::log_info!(
            "TLS 走平台原生后端（native-tls）以协商旧协议：启用集合 {:?}",
            opts.protocols.normalized().enabled
        );
        return build_native(opts).map(|a| TlsAcceptor::Native(Arc::new(a)));
    }
    #[cfg(not(feature = "native-tls"))]
    if opts.protocols.wants_legacy() {
        crate::log_warn!(
            "ssl_protocols 含 TLSv1/TLSv1.1，但本次构建未启用 `--features native-tls`：这些旧版本将被忽略，仅提供 TLS1.2/1.3"
        );
    }
    let cfg = certs::build_server_config(opts)?;
    Ok(TlsAcceptor::Rustls(tokio_rustls::TlsAcceptor::from(Arc::new(
        cfg,
    ))))
}

/// 原生后端接受器：取默认证书（无 SNI 多证书），按启用集合钉死 min/max 协议版本。
#[cfg(feature = "native-tls")]
fn build_native(opts: &TlsOptions) -> Result<tokio_native_tls::TlsAcceptor, String> {
    use native_tls::{Identity, TlsAcceptor as NtAcceptor};

    let spec = opts
        .specs
        .first()
        .ok_or("native TLS：该监听没有配置任何证书")?;
    let cert = std::fs::read(&spec.cert).map_err(|e| format!("读取证书 {} 失败: {e}", spec.cert.display()))?;
    let key = std::fs::read(&spec.key).map_err(|e| format!("读取私钥 {} 失败: {e}", spec.key.display()))?;
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
