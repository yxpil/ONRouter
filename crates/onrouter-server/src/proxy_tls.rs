//! 反向代理**客户端** TLS 层：让 `proxy_pass https://…` / `wss://…` 能作为客户端连到加密后端。
//!
//! 与 `tls.rs`（服务端握手）相对，这里面向 rustls **ClientConfig**，并把"明文 TCP"和
//! "TLS over TCP"两种后端流统一成一个 `ProxyStream`，实现 hyper legacy 客户端要求的
//! `Service<Uri>` + `Connection`，于是 http/https 后端**共用同一套连接池**（hyper 按 URI
//! 的 scheme+authority 自然分池）。
//!
//! 纯 Rust：根证书来自 `proxy_ssl_trusted_certificate`（rustls-pemfile 解析）；`proxy_ssl_verify off`
//! 走 `AcceptAll` danger verifier（自签/内网常用）。**不引入 webpki-roots/native-certs**——本机离线
//! registry 里只有 rustls/rustls-pemfile，故系统根证书库未链接（README 已说明该限制）。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::connect::{Connection, Connected};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

enum ProxyStreamInner {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// hyper 与后端之间统一的流：明文 TCP 或 rustls 客户端 TLS 流。
/// 额外携带 `proxy_send_timeout` 看门狗：单次写操作（headers/body/flush）一旦在内核
/// 写缓冲上阻塞超过该时长即报错断开，语义对齐 nginx 的"两次写操作之间"。
pub struct ProxyStream {
    inner: ProxyStreamInner,
    send_timeout: Option<Duration>,
    /// 当前这次写操作已经等待的时长；Ready 时清空，下次写重新计时。
    write_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

/// 单次内核写的上限。Windows IOCP 的 loopback 快速路径会把超大 send 整块入队
/// （实测 64MB 一次 poll_write 立即返回），内核背压不体现在 Pending 上，
/// send 看门狗就永远等不到超时；切成 64KB 后各平台都能看到真实背压。
const MAX_WRITE_CHUNK: usize = 64 * 1024;

impl ProxyStream {
    fn plain(tcp: TcpStream, send_timeout: Option<Duration>) -> Self {
        ProxyStream {
            inner: ProxyStreamInner::Plain(tcp),
            send_timeout,
            write_deadline: None,
        }
    }

    fn tls(stream: tokio_rustls::client::TlsStream<TcpStream>, send_timeout: Option<Duration>) -> Self {
        ProxyStream {
            inner: ProxyStreamInner::Tls(Box::new(stream)),
            send_timeout,
            write_deadline: None,
        }
    }

    /// 写/刷盘阻塞时启用的看门狗；返回 true 表示已经超时（内部计时器已复位）。
    fn write_timed_out(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(t) = self.send_timeout else {
            return false;
        };
        let deadline = self
            .write_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(t)));
        if deadline.as_mut().poll(cx).is_ready() {
            self.write_deadline = None;
            true
        } else {
            false
        }
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            ProxyStreamInner::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ProxyStreamInner::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let chunk = if buf.len() > MAX_WRITE_CHUNK {
            &buf[..MAX_WRITE_CHUNK]
        } else {
            buf
        };
        let polled = match &mut this.inner {
            ProxyStreamInner::Plain(s) => Pin::new(s).poll_write(cx, chunk),
            ProxyStreamInner::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, chunk),
        };
        match polled {
            Poll::Ready(r) => {
                this.write_deadline = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                if this.write_timed_out(cx) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "proxy_send_timeout: 上游写空闲超时",
                    )));
                }
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = match &mut this.inner {
            ProxyStreamInner::Plain(s) => Pin::new(s).poll_flush(cx),
            ProxyStreamInner::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        };
        match polled {
            Poll::Ready(r) => {
                this.write_deadline = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                if this.write_timed_out(cx) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "proxy_send_timeout: 上游写空闲超时",
                    )));
                }
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = match &mut this.inner {
            ProxyStreamInner::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ProxyStreamInner::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        };
        match polled {
            Poll::Ready(r) => {
                this.write_deadline = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                if this.write_timed_out(cx) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "proxy_send_timeout: 上游写空闲超时",
                    )));
                }
                Poll::Pending
            }
        }
    }
}

impl Connection for ProxyStream {
    fn connected(&self) -> Connected {
        // 统一宣告 http/1.1：ALPN 已在 ClientConfig 钉死 h1，h2 后端暂不作为代理目标。
        Connected::new()
    }
}

// hyper 的 legacy `Connect` 要求连接类型实现 hyper 自己的 `rt::Read`/`rt::Write`
// （而非 tokio 的 trait），故把已实现的 tokio AsyncRead/AsyncWrite 桥接过去。
impl hyper::rt::Read for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // 与 hyper_util::rt::TokioIo 同构：把游标的未填充区交给 tokio ReadBuf，
        // 读后再据实推进游标。
        let n = unsafe {
            let mut tbuf = ReadBuf::uninit(buf.as_mut());
            match AsyncRead::poll_read(self, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };
        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

/// `proxy_ssl_*` 指令的解析产物；决定 https/wss 后端握手时的证书校验策略与 SNI。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsPolicy {
    /// `proxy_ssl_verify on|off`（默认 on）。
    pub verify: bool,
    /// `proxy_ssl_server_name on|off`（默认 on）——关闭则不发 SNI。
    pub send_sni: bool,
    /// `proxy_ssl_name <host>`：覆盖 SNI/校验用的主机名（默认取 URI host）。
    pub server_name: Option<String>,
    /// `proxy_ssl_trusted_certificate <path>`：PEM CA 束，构建根证书库。
    pub trusted_cert: Option<String>,
    /// `proxy_ssl_certificate <path>`：客户端证书链 PEM（向后端出示，实现 mTLS）。
    pub client_cert: Option<String>,
    /// `proxy_ssl_certificate_key <path>`：客户端私钥 PEM（PKCS8/RSA/EC）。
    pub client_key: Option<String>,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        TlsPolicy {
            verify: true,
            send_sni: true,
            server_name: None,
            trusted_cert: None,
            client_cert: None,
            client_key: None,
        }
    }
}

impl TlsPolicy {
    /// 连接池分组用的指纹：同一 (超时,keepalive) 下，TLS 策略不同必须分池，
    /// 否则 A location 的"verify off"会污染 B location 的连接器。
    pub fn fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.verify.hash(&mut h);
        self.send_sni.hash(&mut h);
        self.server_name.hash(&mut h);
        self.trusted_cert.hash(&mut h);
        self.client_cert.hash(&mut h);
        self.client_key.hash(&mut h);
        h.finish()
    }

    /// 构建 rustls 客户端配置。`verify on` 且无 trusted cert → 明确报错（本机未链接系统根库）。
    /// 若同时给出 `proxy_ssl_certificate` + `proxy_ssl_certificate_key`，则向后端出示客户端证书（mTLS）。
    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>, String> {
        let provider = Arc::new(default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
            .map_err(|e| format!("TLS 协议版本配置失败: {e}"))?;
        // 先得到"待选客户端证书"阶段的 builder（两种证书校验分支返回同一类型）。
        let wants_cert = if !self.verify {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAll))
        } else {
            let mut store = RootCertStore::empty();
            if let Some(path) = &self.trusted_cert {
                let data = std::fs::read(path)
                    .map_err(|e| format!("读取 proxy_ssl_trusted_certificate {path} 失败: {e}"))?;
                let mut cur = data.as_slice();
                for c in rustls_pemfile::certs(&mut cur) {
                    let c = c.map_err(|e| format!("解析 CA PEM 失败: {e}"))?;
                    store.add_parsable_certificates([c]);
                }
            }
            if store.is_empty() {
                return Err(
                    "proxy_ssl_verify on 需要 proxy_ssl_trusted_certificate 指定可信 CA 束 \
                     （本构建为纯 Rust 离线，未链接系统根证书库）；或改用 proxy_ssl_verify off"
                        .to_string(),
                );
            }
            builder.with_root_certificates(store)
        };
        // 客户端证书（mTLS）：两者都给才启用；缺任一按 nginx 语义忽略客户端证书（只服务端认证）。
        let mut cfg: ClientConfig = match (&self.client_cert, &self.client_key) {
            (Some(cert_path), Some(key_path)) => {
                let cert_data = std::fs::read(cert_path)
                    .map_err(|e| format!("读取 proxy_ssl_certificate {cert_path} 失败: {e}"))?;
                let mut certs: Vec<CertificateDer<'static>> = Vec::new();
                let mut cur = cert_data.as_slice();
                for c in rustls_pemfile::certs(&mut cur) {
                    certs.push(c.map_err(|e| format!("解析客户端证书 PEM 失败: {e}"))?);
                }
                if certs.is_empty() {
                    return Err(format!("proxy_ssl_certificate {cert_path} 未含任何证书"));
                }
                let key_data = std::fs::read(key_path)
                    .map_err(|e| format!("读取 proxy_ssl_certificate_key {key_path} 失败: {e}"))?;
                let mut kcur = key_data.as_slice();
                let key = rustls_pemfile::private_key(&mut kcur)
                    .map_err(|e| format!("解析客户端私钥 PEM 失败: {e}"))?
                    .ok_or_else(|| "proxy_ssl_certificate_key 未含可用私钥（PKCS8/RSA/EC）".to_string())?;
                wants_cert
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| format!("配置客户端证书失败: {e}"))?
            }
            _ => wants_cert.with_no_client_auth(),
        };
        // 只谈 HTTP/1.1：hyper legacy 客户端只说 h1，ALPN 必须与之相符。
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

/// `proxy_ssl_verify off` 用的不做校验的 verifier（自签/内网常见需求）。
#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // 声称全支持即可（校验被跳过）；覆盖常见签名套件。
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// 供 cosocket 的 `sock:tlshandshake` 复用：**不校验证书**（AcceptAll）的客户端配置，
/// 不钉 ALPN（区别于代理用途——cosocket 可能是裸协议/私有协议）。自签后端可用。
pub fn insecure_client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .expect("支持的 TLS 版本")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// 供 `sock:tlshandshake({verify=true, ca=<path>})`：从 PEM CA 束构建校验型客户端配置（无 ALPN）。
pub fn verify_client_config(ca_pem_path: &str) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| format!("TLS 协议版本配置失败: {e}"))?;
    let mut store = RootCertStore::empty();
    let data = std::fs::read(ca_pem_path)
        .map_err(|e| format!("读取 CA PEM {ca_pem_path} 失败: {e}"))?;
    let mut cur = data.as_slice();
    for c in rustls_pemfile::certs(&mut cur) {
        let c = c.map_err(|e| format!("解析 CA PEM 失败: {e}"))?;
        store.add_parsable_certificates([c]);
    }
    if store.is_empty() {
        return Err("verify=true 需要有效 ca 证书束（本构建为纯 Rust 离线，未链接系统根证书库）".to_string());
    }
    let cfg = builder.with_root_certificates(store).with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// hyper legacy 客户端连接器：按 URI scheme 选择明文 TCP 或 rustls-over-TCP。
/// `Clone` 以便连接池复用；`Service<Uri>` 是 hyper `Connect` 的公开实现口。
#[derive(Clone)]
pub struct ProxyConnector {
    pub connect_timeout: Duration,
    /// `proxy_send_timeout`：0 表示不限制（nginx 语义）。
    pub send_timeout: Duration,
    /// https/wss 时才需要；None 表示本连接器不带 TLS（纯 http）。
    pub tls: Option<Arc<ClientConfig>>,
    sni_override: Option<String>,
}

impl ProxyConnector {
    pub fn new(
        connect_timeout: Duration,
        send_timeout: Duration,
        tls: Option<Arc<ClientConfig>>,
        policy: &TlsPolicy,
    ) -> Self {
        ProxyConnector {
            connect_timeout,
            send_timeout,
            tls,
            sni_override: policy.server_name.clone(),
        }
    }
}

impl tower_service::Service<Uri> for ProxyConnector {
    type Response = ProxyStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<ProxyStream, io::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let tls = self.tls.clone();
        let timeout = self.connect_timeout;
        let send_timeout = (!self.send_timeout.is_zero()).then_some(self.send_timeout);
        let sni_override = self.sni_override.clone();
        Box::pin(async move {
            let is_https = dst.scheme_str() == Some("https");
            let host = dst
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "后端 URI 无主机名"))?
                .to_string();
            let port = dst.port_u16().unwrap_or(if is_https { 443 } else { 80 });
            let tcp = tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "连接后端超时"))?
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("连接后端失败 {host}:{port}: {e}"))
                })?;
            let _ = tcp.set_nodelay(true);
            if !is_https {
                return Ok(ProxyStream::plain(tcp, send_timeout));
            }
            let cfg = tls.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "https 后端缺少 TLS 配置（需 proxy_ssl_trusted_certificate 或 proxy_ssl_verify off）",
                )
            })?;
            let sni_host = sni_override.clone().unwrap_or_else(|| host.clone());
            // rustls 客户端必须携带一个 DNS 形 ServerName（IP 字面量不能作 SNI）。
            // 注：proxy_ssl_server_name off 在本实现里是"接受但无效"——纯 Rust rustls 客户端总会发
            //     SNI；需要连 IP 型 https 后端时请用 hostname（README 已注明该限制）。
            let name = ServerName::try_from(sni_host.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("非法 SNI 主机名 {sni_host}: {e}")))?
                .to_owned();
            let connector = TlsConnector::from(cfg);
            let stream = connector
                .connect(name, tcp)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("后端 TLS 握手失败 {sni_host}: {e}"),
                    )
                })?;
            Ok(ProxyStream::tls(stream, send_timeout))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用 rcgen 生成一对自签（证书+私钥）写入临时目录，返回路径。
    fn write_client_pair(dir: &std::path::Path, tag: &str) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["client.test".to_string()])
            .expect("rcgen 生成客户端证书");
        let cp = dir.join(format!("{tag}-cert.pem"));
        let kp = dir.join(format!("{tag}-key.pem"));
        std::fs::write(&cp, cert.cert.pem()).unwrap();
        std::fs::write(&kp, cert.key_pair.serialize_pem()).unwrap();
        (
            cp.to_string_lossy().into_owned(),
            kp.to_string_lossy().into_owned(),
        )
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("onrouter-mtls-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mtls_client_cert_config_builds_and_splits_pool() {
        let dir = tmp_dir("build");
        let (cp, kp) = write_client_pair(&dir, "c");
        // verify off + 客户端证书 → 应能构建（走 with_client_auth_cert）
        let policy = TlsPolicy {
            verify: false,
            client_cert: Some(cp.clone()),
            client_key: Some(kp.clone()),
            ..Default::default()
        };
        assert!(policy.build_client_config().is_ok(), "mTLS 客户端配置应构建成功");

        // 仅差客户端证书的策略，指纹必须不同（否则会串池）
        let plain = TlsPolicy {
            verify: false,
            ..Default::default()
        };
        assert_ne!(plain.fingerprint(), policy.fingerprint());

        // 只给 cert 不给 key → 按 nginx 语义忽略客户端证书（仍能构建，走 no_client_auth）
        let cert_only = TlsPolicy {
            verify: false,
            client_cert: Some(cp),
            client_key: None,
            ..Default::default()
        };
        assert!(cert_only.build_client_config().is_ok());
        // 且与两者皆无的指纹不同（cert 路径已参与指纹）
        assert_ne!(plain.fingerprint(), cert_only.fingerprint());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mtls_missing_client_cert_file_errors() {
        let policy = TlsPolicy {
            verify: false,
            client_cert: Some("no-such-client-cert.pem".into()),
            client_key: Some("no-such-client-key.pem".into()),
            ..Default::default()
        };
        let err = policy.build_client_config().unwrap_err();
        assert!(err.contains("proxy_ssl_certificate"), "{err}");
    }

    #[tokio::test]
    async fn send_timeout_fires_when_upstream_stops_reading() {
        use tokio::io::AsyncWriteExt;
        use tower_service::Service;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let policy = TlsPolicy {
            verify: false,
            ..Default::default()
        };
        let mut conn = ProxyConnector::new(
            Duration::from_secs(1),
            Duration::from_millis(300),
            None,
            &policy,
        );
        let uri: Uri = format!("http://{addr}").parse().unwrap();
        let mut stream = conn.call(uri).await.unwrap();
        // Windows loopback 对单次超大 send 有快速入队路径；按 TLS 记录/分块体的大小循环写，
        // 才会真正压到内核缓冲并返回 Pending。
        let chunk = vec![0u8; 64 * 1024];
        let write = async {
            loop {
                stream.write_all(&chunk).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), std::io::Error>(())
        };
        let err = tokio::time::timeout(Duration::from_secs(3), write)
            .await
            .expect("写入不应挂死")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    }

    #[tokio::test]
    async fn send_timeout_disabled_does_not_abort_writes() {
        use tokio::io::AsyncWriteExt;
        use tower_service::Service;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut sink = vec![0u8; 64 * 1024];
            while let Ok(n) = tokio::io::AsyncReadExt::read(&mut s, &mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });
        let policy = TlsPolicy::default();
        let mut conn = ProxyConnector::new(Duration::from_secs(1), Duration::ZERO, None, &policy);
        let uri: Uri = format!("http://{addr}").parse().unwrap();
        let mut stream = conn.call(uri).await.unwrap();
        let payload = vec![0u8; 1024 * 1024];
        tokio::time::timeout(Duration::from_secs(5), stream.write_all(&payload))
            .await
            .expect("禁用看门狗后写入应正常完成")
            .unwrap();
    }
}
