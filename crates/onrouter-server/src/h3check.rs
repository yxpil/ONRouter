//! orr-h3check —— 自研 HTTP/3 客户端探针（quinn + h3）。
//!
//! 本机 curl/Node 均不支持 HTTP/3，故用与 ONRouter 服务端相同的 h3/quinn 栈做真实流量验证：
//! 真握手（QUIC over UDP + TLS1.3/ALPN h3）、真收发请求流、真读响应体，而非代码审查。
//!
//! 用法：`orr-h3check <ip:port> <sni> <path> <mode> [n]`
//!   mode=single  -> GET 一次，打印 STATUS= / PROTO= / BODY=
//!   mode=streams -> 同一连接并发开 n 个请求流，打印 STREAMS=<HTTP 200 的数量>
//!
//! 证书：通过环境变量 `ORR_H3_CERT`（默认 `certs_scenario/server.pem`）把服务端自签名证书
//! 作为受信根加载；SAN 必须含 <sni>，否则握手期证书校验失败。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use futures_util::future;

fn load_roots(pem_path: &str) -> rustls::RootCertStore {
    let f = std::fs::File::open(pem_path)
        .unwrap_or_else(|e| panic!("打开证书 {pem_path} 失败: {e}"));
    let mut reader = std::io::BufReader::new(f);
    let mut store = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut reader) {
        let c = c.expect("解析证书 PEM 失败");
        store.add(c).expect("把自签名证书加入受信根失败");
    }
    store
}

fn client_endpoint(sni: &str) -> quinn::Endpoint {
    let _ = sni;
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

    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .expect("QUIC 客户端 TLS 配置失败");
    let client = quinn::ClientConfig::new(Arc::new(quic_cfg));

    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut endpoint = quinn::Endpoint::client(bind).expect("绑定 UDP 客户端失败");
    endpoint.set_default_client_config(client);
    endpoint
}

type SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

async fn do_request(send_req: &mut SendReq, sni: &str, path: &str) -> Option<(u16, String, String)> {
    let uri = format!("https://{sni}{path}");
    let req = http::Request::builder().method("GET").uri(uri).body(()).ok()?;
    let mut stream = send_req.send_request(req).await.ok()?;
    stream.finish().await.ok()?;
    let resp = stream.recv_response().await.ok()?;
    let status = resp.status().as_u16();
    let proto = format!("{:?}", resp.version());
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
    Some((status, proto, String::from_utf8_lossy(&body).to_string()))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!("用法: orr-h3check <ip:port> <sni> <path> <single|streams> [n]");
        std::process::exit(2);
    }
    let addr: SocketAddr = args[0].parse().expect("addr 需为 ip:port");
    let sni = args[1].clone();
    let path = args[2].clone();
    let mode = args[3].clone();
    let n: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(3);

    let endpoint = client_endpoint(&sni);
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

    if mode == "streams" {
        let mut handles = Vec::new();
        for _ in 0..n {
            let mut sr = send_req.clone();
            let p = path.clone();
            let s = sni.clone();
            handles.push(tokio::spawn(async move {
                matches!(do_request(&mut sr, &s, &p).await, Some((200, _, _)))
            }));
        }
        let mut ok = 0usize;
        for h in handles {
            if h.await.unwrap_or(false) {
                ok += 1;
            }
        }
        println!("STREAMS={ok}");
    } else {
        match do_request(&mut send_req, &sni, &path).await {
            Some((status, proto, body)) => {
                println!("STATUS={status}");
                println!("PROTO={proto}");
                println!("BODY={body}");
            }
            None => {
                println!("ERROR=request");
                std::process::exit(3);
            }
        }
    }

    drv.abort();
    conn.close(quinn::VarInt::from_u32(0), b"done");
    endpoint.wait_idle().await;
}
