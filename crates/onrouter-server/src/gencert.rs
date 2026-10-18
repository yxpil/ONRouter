//! orr-gencert —— ONRouter 自签名证书签发工具（开发/内网用）。
//!
//! 用法：`orr-gencert [cert.pem] [key.pem] [域名...]`
//! 默认输出 `cert.pem` / `key.pem`，SAN 含 localhost / 127.0.0.1。

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cert_path, key_path, sans) = match args.len() {
        0 => ("cert.pem".to_string(), "key.pem".to_string(), vec![]),
        1 => (args[0].clone(), "key.pem".to_string(), vec![]),
        2 => (args[0].clone(), args[1].clone(), vec![]),
        _ => (args[0].clone(), args[1].clone(), args[2..].to_vec()),
    };
    let subjects: Vec<String> = if sans.is_empty() {
        vec!["localhost".into(), "127.0.0.1".into()]
    } else {
        sans
    };

    let cert = rcgen::generate_simple_self_signed(subjects.clone())
        .unwrap_or_else(|e| {
            eprintln!("[orr-gencert] 生成证书失败: {e}");
            std::process::exit(1);
        });

    write(&cert_path, cert.cert.pem());
    write(&key_path, cert.key_pair.serialize_pem());
    println!("[orr-gencert] 已生成: {cert_path} + {key_path} (SAN: {})", subjects.join(", "));
}

fn write(path: &str, content: String) {
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(p, content).unwrap_or_else(|e| {
        eprintln!("[orr-gencert] 写 {path} 失败: {e}");
        std::process::exit(1);
    });
}
