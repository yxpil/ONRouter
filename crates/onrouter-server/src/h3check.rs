//! orr-h3check —— 自研 HTTP/3 客户端探针（quinn + h3）。
//!
//! 本机 curl/Node 均不支持 HTTP/3，故用与 ONRouter 服务端相同的 h3/quinn 栈做真实流量验证：
//! 真握手（QUIC over UDP + TLS1.3/ALPN h3）、真收发请求流、真读响应体，而非代码审查。
//!
//! 用法：`orr-h3check <ip:port> <sni> <path> <mode> [n]`
//!   single  -> GET 一次：STATUS= / PROTO= / BODY=
//!   streams -> 同一连接并发 n 个请求流：STREAMS=<拿到 200 的数量>
//!   detail  -> GET 一次：STATUS= / PROTO= / LEN= / SHA= / 每行一个 HDR=
//!   head    -> HEAD 一次：同 detail（body 必须是 0 字节）
//!   post    -> POST 一次（body 取自 `ORRH3_BODY` 指向的文件）：同 detail
//!   many    -> 同一连接**串行**发 n 个请求：每行 REQ=i STATUS= LEN= SHA=，末尾 SUMMARY=ok/n
//!   sse     -> GET 一个流式响应，逐帧打印 FRAME=<序号> AT=<毫秒> BYTES=<n>，末尾 FRAMES=<总数>
//!   cancel  -> 并发开 n 条流、发出请求后立刻丢弃（不读响应），随后正常发一个请求：
//!              CANCELLED=<n> THEN=<状态码>（看网关有没有被半途而废的流拖住）
//!
//! 环境变量：
//!   ORR_H3_CERT  受信根（默认 `certs_scenario/server.pem`；SAN 必须含 <sni>；可以是多张证书拼成的包）
//!   ORRH3_AUTHORITY  `:authority` 覆写（默认与 <sni> 相同）——SNI 与站点分开时用
//!   ORRH3_HDRS   额外请求头，`;` 分隔、`:` 分键值：`cookie:sid=A;range:bytes=0-99`
//!   ORRH3_BODY   post 模式请求体的文件路径

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use futures_util::future;

fn load_roots(pem_path: &str) -> rustls::RootCertStore {
    let f =
        std::fs::File::open(pem_path).unwrap_or_else(|e| panic!("打开证书 {pem_path} 失败: {e}"));
    let mut reader = std::io::BufReader::new(f);
    let mut store = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut reader) {
        let c = c.expect("解析证书 PEM 失败");
        store.add(c).expect("把自签名证书加入受信根失败");
    }
    store
}

fn client_endpoint() -> quinn::Endpoint {
    let cert_env =
        std::env::var("ORR_H3_CERT").unwrap_or_else(|_| "certs_scenario/server.pem".into());
    let roots = load_roots(&cert_env);
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3 客户端配置失败")
    .with_root_certificates(roots)
    .with_no_client_auth();
    // 必须协商 ALPN=h3：服务端 build_quic_server_config 只接受 h3，ALPN 不匹配会被拒绝
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_cfg =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC 客户端 TLS 配置失败");
    let client = quinn::ClientConfig::new(Arc::new(quic_cfg));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut endpoint = quinn::Endpoint::client(bind).expect("绑定 UDP 客户端失败");
    endpoint.set_default_client_config(client);
    endpoint
}

type SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// 一次请求。头由 `ORRH3_HDRS` 注入，业务套件因此能测 cookie 限流、Range、
/// accept-encoding 这类"真实客户端会带"的东西，而不是只能发裸 GET。
struct Spec {
    method: http::Method,
    path: String,
    body: Option<Vec<u8>>,
}

fn env_headers() -> Vec<(String, String)> {
    match std::env::var("ORRH3_HDRS") {
        Ok(v) => v
            .split(';')
            .filter_map(|kv| {
                let (k, val) = kv.split_once(':')?;
                let k = k.trim();
                if k.is_empty() {
                    return None;
                }
                Some((k.to_string(), val.trim().to_string()))
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn build(sni: &str, spec: &Spec) -> Option<http::Request<()>> {
    // `ORRH3_AUTHORITY` 让 SNI 与 `:authority` 分开：多证书 / 多站点的单端口上，
    // "出示哪张证书"由 SNI 在握手期决定，"哪个站应答"由 authority 决定。
    // 不分开就只能测两本账一致的情形，测不出它们**不同**的时候各自对不对。
    let authority = std::env::var("ORRH3_AUTHORITY").unwrap_or_else(|_| sni.to_string());
    let mut b = http::Request::builder()
        .method(spec.method.clone())
        .uri(format!("https://{authority}{}", spec.path));
    for (k, v) in env_headers() {
        b = b.header(k, v);
    }
    b.body(()).ok()
}

fn sha256_hex(b: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, b);
    d.as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn get(path: &str) -> Spec {
    Spec {
        method: http::Method::GET,
        path: path.to_string(),
        body: None,
    }
}

/// 发一个请求并读完整响应。返回 (状态码, HTTP 版本, 排序后的响应头, body, trailers)。
async fn request(
    send_req: &mut SendReq,
    sni: &str,
    spec: &Spec,
) -> Option<(u16, String, Vec<(String, String)>, Vec<u8>, bool)> {
    let req = build(sni, spec)?;
    let mut stream = send_req.send_request(req).await.ok()?;
    if let Some(body) = &spec.body {
        stream.send_data(Bytes::from(body.clone())).await.ok()?;
    }
    stream.finish().await.ok()?;
    let resp = stream.recv_response().await.ok()?;
    let status = resp.status().as_u16();
    let proto = format!("{:?}", resp.version());
    let mut hdrs: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    hdrs.sort();
    let mut body: Vec<u8> = Vec::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut buf)) => {
                let n = buf.remaining();
                if n == 0 {
                    continue;
                }
                let chunk = buf.copy_to_bytes(n);
                body.extend_from_slice(&chunk);
            }
            Ok(None) | Err(_) => break,
        }
    }
    // trailers：h3 把它们放在 body 之后，读一次看这一路到底有没有
    let trailers = match stream.recv_trailers().await {
        Ok(Some(t)) => !t.is_empty(),
        _ => false,
    };
    Some((status, proto, hdrs, body, trailers))
}

async fn simple(send_req: &mut SendReq, sni: &str, path: &str) -> Option<u16> {
    request(send_req, sni, &get(path))
        .await
        .map(|(status, _, _, _, _)| status)
}

fn print_detail(
    status: u16,
    proto: &str,
    hdrs: &[(String, String)],
    body: &[u8],
    trailers: bool,
) {
    println!("STATUS={status}");
    println!("PROTO={proto}");
    println!("LEN={}", body.len());
    println!("SHA={}", sha256_hex(body));
    println!("TRAILERS={}", if trailers { 1 } else { 0 });
    // 原始字节落到临时文件：套件因此能做真正的逐字节对比（gzip 解压、Range 分片内容），
    // 而不是只能比摘要
    if !body.is_empty() {
        let dir = std::env::temp_dir().join(format!("qbiz-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let fp = dir.join("resp.bin");
        if std::fs::write(&fp, body).is_ok() {
            println!("FILE={}", fp.display());
        }
    }
    for (k, v) in hdrs {
        println!("HDR={k}: {v}");
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!(
            "用法: orr-h3check <ip:port> <sni> <path> \
             <single|streams|detail|head|post|many|sse|cancel> [n]"
        );
        std::process::exit(2);
    }
    let addr: SocketAddr = args[0].parse().expect("addr 需为 ip:port");
    let sni = args[1].clone();
    let path = args[2].clone();
    let mode = args[3].clone();
    let n: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(3);

    let endpoint = client_endpoint();
    let connecting = match endpoint.connect(addr, &sni) {
        Ok(c) => c,
        Err(e) => {
            println!("ERROR=connect: {e}");
            std::process::exit(3);
        }
    };
    let conn = match tokio::time::timeout(Duration::from_secs(8), connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            println!("ERROR=handshake: {e}");
            std::process::exit(3);
        }
        Err(_) => {
            println!("ERROR=handshake-timeout");
            std::process::exit(3);
        }
    };

    // 握手成功后先把"服务端实际出示了哪张证书"打出来：多证书 / 多 SNI 的单端口要断言的是
    // 指纹，而不只是"握手成了"。h3 与 h2 走的是同一本 SNI 证书账，这条把 h3 那半边也变成可见的。
    // quinn 的 rustls 会话把链以 `Vec<CertificateDer>` 交出来（见 quinn-proto 的 `peer_identity`）。
    if let Some(id) = conn.peer_identity() {
        if let Some(chain) = id.downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>() {
            if let Some(leaf) = chain.first() {
                println!("PEER_SHA256={}", sha256_hex(leaf.as_ref()));
            }
        }
    }

    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_req) = match h3::client::new(h3_conn).await {
        Ok(v) => v,
        Err(e) => {
            println!("ERROR=h3-new: {e:?}");
            std::process::exit(3);
        }
    };
    // h3 客户端连接需要持续驱动控制流/QPACK
    let drv = tokio::spawn(async move {
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    match mode.as_str() {
        "streams" => {
            let mut handles = Vec::new();
            for _ in 0..n {
                let mut sr = send_req.clone();
                let p = path.clone();
                let s = sni.clone();
                handles.push(tokio::spawn(async move {
                    matches!(simple(&mut sr, &s, &p).await, Some(200))
                }));
            }
            let mut ok = 0usize;
            for h in handles {
                if h.await.unwrap_or(false) {
                    ok += 1;
                }
            }
            println!("STREAMS={ok}");
        }
        "head" => {
            let spec = Spec {
                method: http::Method::HEAD,
                path: path.clone(),
                body: None,
            };
            match request(&mut send_req, &sni, &spec).await {
                Some((status, proto, hdrs, body, tr)) => print_detail(status, &proto, &hdrs, &body, tr),
                None => {
                    println!("ERROR=request");
                    std::process::exit(3);
                }
            }
        }
        "post" => {
            let file = std::env::var("ORRH3_BODY").unwrap_or_default();
            let body = std::fs::read(&file).unwrap_or_default();
            let spec = Spec {
                method: http::Method::POST,
                path: path.clone(),
                body: Some(body),
            };
            match request(&mut send_req, &sni, &spec).await {
                Some((status, proto, hdrs, resp, tr)) => {
                    print_detail(status, &proto, &hdrs, &resp, tr)
                }
                None => {
                    println!("ERROR=request");
                    std::process::exit(3);
                }
            }
        }
        "detail" => match request(&mut send_req, &sni, &get(&path)).await {
            Some((status, proto, hdrs, body, tr)) => print_detail(status, &proto, &hdrs, &body, tr),
            None => {
                println!("ERROR=request");
                std::process::exit(3);
            }
        },
        "many" => {
            // 同一条 h3 连接上串行发 n 个请求：限流与缓存的判定需要"确定性的 N 次"
            let mut ok = 0usize;
            for i in 0..n {
                match request(&mut send_req, &sni, &get(&path)).await {
                    Some((status, _proto, _hdrs, body, _tr)) => {
                        if status == 200 {
                            ok += 1;
                        }
                        println!(
                            "REQ={i} STATUS={status} LEN={} SHA={}",
                            body.len(),
                            sha256_hex(&body)
                        );
                    }
                    None => println!("REQ={i} STATUS=0 LEN=0 SHA=none"),
                }
            }
            println!("SUMMARY={ok}/{n}");
        }
        "sse" => {
            // 逐帧收：证明"服务端每 flush 一帧就到一帧"，而不是整份缓冲完再给
            let mut stream = match send_req.send_request(build(&sni, &get(&path)).unwrap()).await {
                Ok(s) => s,
                Err(e) => {
                    println!("ERROR=request: {e}");
                    std::process::exit(3);
                }
            };
            let _ = stream.finish().await;
            // h3 的状态机要求先收响应头再收数据帧；跳过这一步的话一帧都读不到，
            // 看起来像"网关没有流式转发"
            let status = stream
                .recv_response()
                .await
                .map_or(0, |r| r.status().as_u16());
            println!("SSE_STATUS={status}");
            let t0 = Instant::now();
            let mut frames = 0usize;
            loop {
                match tokio::time::timeout(Duration::from_secs(12), stream.recv_data()).await {
                    Ok(Ok(Some(mut buf))) => {
                        let have = buf.remaining();
                        if have == 0 {
                            continue;
                        }
                        frames += 1;
                        println!(
                            "FRAME={frames} AT={} BYTES={}",
                            t0.elapsed().as_millis(),
                            have
                        );
                        buf.advance(have);
                    }
                    Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
                }
            }
            println!("FRAMES={frames}");
        }
        "cancel" => {
            let mut opened = 0usize;
            for _ in 0..n {
                if let Some(req) = build(&sni, &get(&path)) {
                    if let Ok(stream) = send_req.clone().send_request(req).await {
                        opened += 1;
                        drop(stream); // 立刻放弃这条流：不读响应
                    }
                }
            }
            let after = simple(&mut send_req, &sni, &path).await.unwrap_or(0);
            println!("CANCELLED={opened} THEN={after}");
        }
        _ => match request(&mut send_req, &sni, &get(&path)).await {
            Some((status, proto, _hdrs, body, _tr)) => {
                println!("STATUS={status}");
                println!("PROTO={proto}");
                println!("BODY={}", String::from_utf8_lossy(&body));
            }
            None => {
                println!("ERROR=request");
                std::process::exit(3);
            }
        },
    }

    drv.abort();
    conn.close(quinn::VarInt::from_u32(0), b"done");
    endpoint.wait_idle().await;
}
